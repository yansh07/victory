# chatengine — Design

A multi-node chat server built from first principles: custom binary protocol, hand-written epoll reactor, durable write-ahead log, Redis Pub/Sub fanout through a hand-written RESP client. No asyncio, no frameworks.

This document records **what was decided, why, and what it costs**. Wire-level details live in [`docs/PROTOCOL.md`](docs/PROTOCOL.md). Numbers in this file are *starting defaults* until `bench/` says otherwise; nothing here claims measured performance.

---

## 1. Goals and non-goals

### Goals

1. Be correct under partial reads, partial writes, slow peers, crashes, and garbage input. Correctness is the product.
2. Make every layer testable without the layers below it (codec without sockets, chat core without a network, bus without Redis).
3. Make durability claims precise and testable: an ACK means fsynced, and a test proves it.
4. Be explicit about trade-offs, including the ones that hurt.

### Non-goals

- Competing with Go/Rust/C on throughput. Python is a deliberate choice (section 4.1).
- Features: reactions, avatars, history search, presence, E2E encryption.
- Serving message history to clients. The WAL exists for durability and recovery, not as a read path (v1).
- TLS in-process. Terminate at HAProxy.
- Windows support. Linux (epoll) is the primary target; a `selectors` fallback exists for macOS/BSD development.

---

## 2. Architecture

### 2.1 Layering

```
 clients ──TCP──► HAProxy (L4) ──► node ──┬──► Redis Pub/Sub (fanout between nodes)
                                          └──► local disk (WAL)

 Inside a node:

   ┌───────────────────────── event-loop thread (all logic, all sockets) ────────────────────────┐
   │                                                                                             │
   │  Reactor ──► Connection ──► FrameDecoder ──► Router (pure logic) ──► Rooms / Sessions       │
   │  (epoll)     (buffers,      (bytes→Frames)        │                                         │
   │  Timers       state FSM,                          ├──► Bus (InProcess | Redis via RESP)     │
   │  Wakeup fd    watermarks)                         └──► WAL queue ─────────┐                 │
   └─────────────────────────────────────────────────────────────────────────┼─────────────────┘
                                                                              ▼
                                                          ┌─── WAL writer thread ───┐
                                                          │ append · group-commit   │
                                                          │ fsync · completion ─────┼──► wakeup fd ─► loop sends ACKs
                                                          └─────────────────────────┘
```

Dependency direction: `codec → connection → reactor → router → bus + WAL`. Each layer knows the one below only through a narrow interface. That is the reason milestones M1 (codec), M4 (core), and M6 (bus) can be tested with zero real networking.

### 2.2 Threads

- **Exactly two**: the event loop, and the WAL writer.
- The event loop owns *all* mutable state: connections, sessions, rooms, sequence counters, timers, the Redis connection. No locks anywhere in the hot path.
- The WAL thread owns the active segment file descriptor and nothing else.
- Communication is by queues (`collections.deque` appends/pops are atomic in CPython) plus a self-pipe/socketpair to wake the loop. See 4.9.

### 2.3 Data flow for one MSG

1. Loop reads bytes from socket → `FrameDecoder` yields a `MSG` frame.
2. `Router` validates (authenticated? member of room? dedupe hit?), assigns `seq` for `(room)` on this node.
3. Record is placed on the WAL queue. The loop does **not** wait.
4. WAL thread appends, group-commits, fsyncs, pushes completions, pokes the wakeup fd.
5. Loop wakes, for each completed record: encode `DELIVER` **once**, enqueue the same bytes to every local member's outbound queue, enqueue `ACK` to the sender, publish to the bus.
6. Write interest is enabled on connections with pending output; the loop flushes as sockets become writable.

---

## 3. Invariants

These are the properties the test suite exists to defend. If one is violated, it is a bug, not a trade-off.

| ID  | Invariant | Defended by |
|-----|-----------|-------------|
| I1  | A `durable=1` ACK is never sent before the corresponding WAL record has been fsynced. | M7 kill -9 test; assertion in completion path |
| I2  | No message is delivered to any client (local or remote) before it is durable on its origin node. | M7, integration tests |
| I3  | For a fixed `(origin_node, room)`, sequence numbers in the WAL are strictly increasing and gap-free. | Replay test, property test |
| I4  | WAL replay yields a consistent prefix: a torn tail is truncated; no record after a bad record in the last segment is applied. | M7 torn-write tests |
| I5  | A connection's outbound queue never exceeds the hard limit; the process's memory is bounded by `connections × hard_limit` plus shared frame bytes. | M3 slow-client test (RSS bounded) |
| I6  | The loop thread never blocks on disk, a sleeping syscall, or a lock. | Loop-lag metric, review |
| I7  | The decoder never allocates proportional to an attacker-claimed length before validating it. | Fuzzing, oversize-header test |
| I8  | `(user, client_msg_id)` within the dedupe window yields at most one WAL record. | Retry test, replay test |
| I9  | A node never re-delivers its own bus publications. | Two-node test |
| I10 | Every ACKed message is in the WAL after a graceful shutdown **and** after a forced one. | M8 tests |

---

## 4. Decisions and trade-offs

Format: **decision → alternatives considered → cost we accept**.

### 4.1 Python

- **Decision:** CPython 3.11+, stdlib only for the core.
- **Why:** The learning target is protocol framing, state machines, I/O multiplexing, backpressure, and durability. Python lets those be the only hard problems.
- **Alternatives:** Go (goroutines hide the reactor, which is the point of the exercise), Rust (borrow checker time spent on memory shapes rather than semantics), C (would work; slower to test and fuzz).
- **Cost:** Interpreter overhead on tight per-frame loops, object allocation per frame, the GIL. A single loop thread means one core of useful work per node; scaling is horizontal (4.16).
- **Mitigations:** Read into a shared scratch buffer and decode with `struct.unpack_from` on `memoryview`; encode each outbound frame once and share it across recipients; coalesce writes per connection per loop iteration; push the one blocking operation (fsync) to a thread, where the GIL is released during the syscall.
- **Honest expectation:** The bottleneck will be per-frame decode and fanout (N queue appends + N `send` calls per message). `bench/` records the profile; the results go at the bottom of this file, whatever they turn out to be.

### 4.2 Own reactor on epoll instead of asyncio

- **Decision:** `select.epoll` backend, with a `selectors`-based fallback behind the same `Backend` interface.
- **Why:** The reactor is the thing being studied. asyncio, uvloop, socketserver, and Twisted are banned because they hide exactly the behavior this project exists to learn.
- **Cost:** More code, more bugs, no ecosystem. Every edge case asyncio already handles (EPOLLHUP vs EPOLLRDHUP, accept storms, EINTR) is ours.
- **Pattern:** Reactor (readiness notification), not Proactor. The kernel tells us a socket *can* be read/written; we do the I/O. io_uring/IOCP invert this (you submit operations and get completions). Reactor fits the portable syscall surface Python exposes.

### 4.3 Level-triggered by default; edge-triggered optional

- **Decision:** Level-triggered epoll for all connections in v1.
- **Why:** Level-triggered tolerates a handler that doesn't fully drain a socket; the next `poll()` reports it again. Edge-triggered requires reading/writing until `EAGAIN` every time or the connection silently hangs, and that mistake is invisible until load.
- **Cost:** More wakeups when data remains unread. Level-triggered also lets us implement *backpressure by simply not reading*: we unregister read interest and the kernel buffer fills.
- **Optional later:** An `EPOLLET` mode with a benchmark comparison, once everything is correct under LT.

### 4.4 Non-blocking I/O discipline

- All sockets are non-blocking. `recv` raising `BlockingIOError` means "nothing now"; `send` may accept **fewer bytes than offered**, and the remainder stays queued.
- **Accept:** loop `accept()` until `BlockingIOError`, bounded per iteration (e.g. 64) to avoid starving existing connections during a connection storm.
- **Fairness:** per-connection read budget per iteration (e.g. 64 KiB). A fast sender can't monopolize the loop.
- **Error handling:** `ECONNRESET`, `EPIPE`, `ETIMEDOUT` → close the connection; they are routine, not exceptional. `EINTR` is retried (PEP 475 handles most). EOF mid-frame → drop partial buffer, close.
- **Write interest is enabled only while output is pending.** Leaving `EPOLLOUT` on an idle writable socket makes epoll return immediately forever and burns 100% CPU. M2 asserts idle CPU is near 0.

### 4.5 Binary, length-prefixed, big-endian protocol

- **Decision:** Fixed 14-byte header (magic, version, type, flags, reserved, request ID, length) + payload. Details in `PROTOCOL.md`.
- **Alternatives:** Line-delimited text (delimiter scanning, escaping, binary-unsafe), JSON (parse cost dominates in Python, no length bound before parse), Protobuf (an external dependency that would hide the framing work).
- **Why:** Length-prefix gives O(1) frame boundary detection and lets us reject oversized frames from the header alone (I7). Magic + version catch protocol mismatches and a client speaking HTTP at us, immediately.
- **Fatal vs non-fatal errors:** Framing errors are fatal (no resync in v1). Payload-level errors on a well-framed message are survivable. Resync heuristics (scan for the magic) are a known source of security bugs and are rejected.
- **Strict parsing:** Reserved bits must be zero and payloads must be consumed exactly. Lenient parsers become de-facto extensions that you can never remove.
- **Cost:** No self-describing schema; evolution is by new frame types or `version = 2`.

### 4.6 TCP is a byte stream: streaming decoder

- `FrameDecoder.feed(data) -> list[Frame]` is a pure state machine: `WAIT_HEADER → WAIT_PAYLOAD → (emit) → WAIT_HEADER`. It holds no sockets and can be tested with arbitrary slicing (M1).
- This is the #1 bug source in network code: one `recv` may deliver half a frame or three frames. The decoder's property test (random frames, random split points, identical output) is the most important test in the repository.

### 4.7 Buffer management

- **Inbound:** One loop-wide 64 KiB scratch `bytearray`; `sock.recv_into(scratch)`. The decoder consumes whole frames straight out of the scratch via `memoryview`. Only an incomplete **tail** is copied into the connection's private buffer. Most reads on a busy connection end on a frame boundary or close to it, so most connections hold nearly zero buffered bytes. Sharing the scratch is safe because the loop is single-threaded.
- **Per-connection buffer:** Starts small (~4 KiB), grows as needed up to `14 + max_payload`, and is released when empty. 10k connections × a fixed 64 KiB buffer would be 640 MiB for nothing.
- **Compaction:** Track a read offset instead of deleting from the front (which is O(n) per frame). Compact (shift the remaining bytes to the start) when the offset passes half the capacity or the buffer empties.
- **Gotcha:** A `bytearray` cannot be resized while a `memoryview` of it is alive (`BufferError`). Resizing and compaction therefore happen only at defined points between decoder passes, after views have been released.
- **Outbound:** A `deque` of `memoryview` chunks plus a byte counter. `send` consumes from the front; a partial send replaces the head chunk with a sliced view (no copy). Optional later: `sendmsg` scatter-gather to cut syscalls.
- **Cost:** Extra complexity for a win that's only visible in a profile. It stays only if `bench/` shows it matters; otherwise it gets removed.

### 4.8 Backpressure and slow consumers

Two limits per connection, measured in queued outbound bytes:

| Threshold         | Default (tune via bench) | Action |
|-------------------|-------------------------:|--------|
| Soft (high water) | 256 KiB                  | Unregister read interest for this connection |
| Low water         | 64 KiB                   | Re-register read interest |
| Hard              | 1 MiB                    | Best-effort `ERROR(SLOW_CONSUMER)`, close |

- **Why stopping reads helps:** If a client can't drain its output, accepting more of its requests produces more ACKs and more output for it. Not reading lets TCP's receive window fill and propagates pressure back to the sender, instead of buffering it in our heap.
- **Why that is not enough:** Pausing reads on *client A* does nothing about *client B's* messages being fanned out *to A*. That is the fanout amplification problem: one inbound message becomes N outbound queue entries, and any one slow recipient accumulates them. **The hard limit is the real protection**; the soft limit only limits self-inflicted load.
- **Policy choice — disconnect, not drop:** Dropping messages for a slow consumer silently corrupts the sequence; a disconnect is loud, bounded, and recoverable (client reconnects). Alternatives (drop-oldest, spill to disk) are rejected for v1.
- **Memory accounting:** Fanout shares one encoded frame across N queues, so true memory is lower than `sum(queue sizes)`. Limits count per-connection logical bytes, which is conservative.
- **Global guard:** A cap on total connections, and (to-do) a cap on total queued bytes across all connections to protect against many mildly slow clients that individually stay under the hard limit.

### 4.9 Single-writer principle and the self-pipe trick

- **Decision:** One owner per piece of state. The loop owns everything except the WAL file. Cross-thread communication is queues only.
- **Wakeup:** The WAL thread appends to a completion `deque` and writes a byte to a non-blocking socketpair whose read end is registered in epoll. This turns "a thread finished something" into an ordinary readiness event, with no polling and no loop timeout hacks. Redundant wakeups are harmless: the loop drains the socketpair and the queue.
- **Alternatives:** Locks around shared state (contention, deadlocks, nondeterministic tests), `queue.Queue` with polling (adds latency or CPU).
- **Cost:** Discipline. Anything touching a socket from the WAL thread is a bug.

### 4.10 Chat core is pure logic

- `Router`, `Sessions`, and `Rooms` take decoded frames and return **actions** (send ACK, send ERROR, deliver, append WAL, publish). They know nothing about sockets or epoll.
- **Why:** Deterministic tests, no timing, no ports. M4 is a table of "given these frames, expect these actions".
- **Cost:** An extra layer of indirection between "message accepted" and "bytes sent".

### 4.11 Ordering model

| Property | v1 |
|----------|----|
| Per-sender FIFO | Yes |
| Per-`(origin_node, room)` order, gap-free | Yes (assigned by the origin node; written to its WAL) |
| Total order across all nodes | **No** |

- **Why:** A single room-wide order across nodes needs a sequencer: a per-room home node (consistent hashing + forwarding), a Redis `INCR` per message (an extra RTT on the hot path, and publish races still need receiver-side reordering), or consensus. Each is a project in itself.
- **What clients see:** Two members on different nodes may see interleavings of concurrent messages differently. Each message carries `(origin_node, seq)`, so clients can detect gaps per origin.
- **Upgrade path:** Home-node sequencing: `hash(room) → owner node`; non-owners forward MSG to the owner via the bus. This is documented rather than built.
- **If an interviewer pushes:** Yes, this is weaker than Slack's ordering model, and that was a conscious scope decision, not an oversight.

### 4.12 Delivery semantics

- **To the sender:** at-least-once. Retry with the same `client_msg_id`; server dedupes on `(user, client_msg_id)` within a bounded window, rebuilt from the WAL on recovery (I8).
- **To recipients on the same node:** delivered once per connection, after durability, if still connected.
- **To recipients on other nodes:** at-most-once (Redis Pub/Sub does not buffer for absent subscribers). Gaps are detectable via `seq`.
- **Exactly-once** is not claimed. What exists is at-least-once plus idempotency, which is the honest version of it.
- **Echo suppression:** Each bus message carries `origin_node`; a node ignores its own publications (I9).
- **Delivery after durability (D4):** We could fan out immediately and ACK later, which lowers recipient latency. We don't: it creates the possibility of a client having seen a message that, after a crash, never existed. The price is that recipient latency includes the group-commit window.

### 4.13 Write-ahead log

**Record framing (little detail on purpose; confirm against `wal.py`):**

```
segment file: wal-<8-digit-index>.log
  header : magic(4) | version(1) | first_lsn(8)
  record : crc32(4) | length(4) | lsn(8) | type(1) | payload(length-9)
           crc covers: length, lsn, type, payload
```

- **Append-only**, segments rotated at a size cap (default 64 MiB). New segment creation is followed by an `fsync` of the **directory**, otherwise a crash can lose the file's existence even though its contents were synced.
- **Group commit:** The writer thread drains everything currently queued, writes it with one `write`, issues one `fsync`, then completes all of those records together. Batching is natural: records that arrive during an fsync form the next batch. No artificial delay timer by default.
- **fsync cost** dominates latency and is hardware-dependent (milliseconds on SSD/cloud disks). Group commit amortizes it: throughput scales with batch size, per-message latency does not improve.
- **CRC:** `zlib.crc32` (the stdlib's IEEE CRC-32, not CRC-32C). Fine for torn-write and bit-rot detection at this scale; hardware CRC-32C would be the production choice.
- **Torn write handling on recovery:**
  - Short read, or CRC mismatch, in the **last** segment's tail → truncate to the last good record and continue (this is what a crash mid-write looks like).
  - CRC mismatch **followed by valid data**, or any corruption in a non-final segment → refuse to start. That is corruption, not a torn tail, and silently truncating would discard acknowledged data.
- **Replay rebuilds:** next `seq` per room, and the per-user dedupe window.
- **Not done in v1:** retention/compaction, segment checksums beyond per-record CRCs, serving history.

### 4.14 Redis Pub/Sub and the hand-written RESP2 client

- **Decision:** Redis Pub/Sub for cross-node fanout; RESP2 client written on top of the reactor (non-blocking, fragmented-read tolerant).
- **Why Pub/Sub:** Simplest fanout primitive that makes a multi-node demo real. Redis Streams (durable, replayable) is the optional upgrade that closes the at-most-once gap.
- **Connections:** A Redis connection in subscribed state only accepts (P)(UN)SUBSCRIBE/PING, so the node holds **two** Redis connections: one subscriber, one publisher.
- **Reconnect:** Exponential backoff with jitter; on reconnect, resubscribe every room channel that has local members. During the outage, local fanout continues; remote nodes miss messages (D3). This must not crash the node (M6 test).
- **Why `redis-py` appears only in tests:** as an independent oracle to check our RESP encoder/decoder against a mature implementation.
- **Known gap:** A message can be durable, ACKed, and **not published** if the node dies between the fsync and the publish. After restart, its sender's retry is deduped (so it's not re-published), and remote subscribers never see it. Closing this needs Streams or a "republish tail of WAL on startup" with receiver-side dedupe on `(origin_node, seq)`. Documented, not hidden.

### 4.15 Timers

- **Decision:** A `heapq` min-heap of `(deadline, id)`; the reactor computes `poll(timeout = max(0, next_deadline − now))` using `time.monotonic()`.
- **Alternatives:** Timer wheel — better asymptotics for millions of timers; not worth the complexity at the thousands scale this runs at.
- **Cancellation:** Lazy deletion with a tombstone set; rebuild the heap when tombstones exceed half of its size.
- **Heartbeat churn avoidance:** Don't reschedule on every inbound frame. Store `last_activity`; when the idle timer fires, check whether the deadline truly passed, otherwise re-arm for the remainder. This keeps the heap off the per-message path.
- **Uses:** HELLO timeout, idle timeout, drain deadline, Redis reconnect backoff, periodic metrics.

### 4.16 Horizontal scaling

- **Decision:** Stateless-ish nodes behind an HAProxy `mode tcp` L4 balancer, `balance leastconn`.
- **Why sticky sessions aren't required:** A session is its TCP connection; nothing about it lives anywhere but that node's memory, and cross-node delivery goes through Redis. A reconnect landing on any node is equivalent.
- **What this costs:** After reconnect, the client must re-`HELLO` and re-`JOIN`; there is no resume in v1. (Resume-from-sequence is an optional feature and would require `version = 2` of the protocol.)
- **HAProxy:** `timeout client`/`timeout server`/`timeout tunnel` must exceed the maximum idle timeout, or HAProxy will cut healthy-but-quiet connections before we do.

### 4.17 Graceful shutdown

States: `RUNNING → DRAINING → FLUSHING → EXIT`.

1. **Signal handler does nothing except record the signal and write to a wakeup fd** (`signal.set_wakeup_fd` or a manual socketpair write). All real work happens in the loop. Signal handlers interrupt arbitrary code; running logic in them is how you get re-entrancy bugs.
2. **DRAINING:** stop `accept`, broadcast `SHUTDOWN(reason=0, deadline_ms)`, reject new `MSG`/`JOIN`.
3. **FLUSHING:** wait for outbound queues to empty or the deadline to pass; wait for the WAL queue to drain and the final fsync to complete (ACK for everything that is still queued).
4. **EXIT:** close sockets, close the WAL, exit code `0`.
5. **Second signal:** exit immediately with a non-zero code. Because of I1, this loses no ACKed data; only un-ACKed in-flight messages (which clients will retry).

### 4.18 Authentication

- Static token(s) from config, compared with `hmac.compare_digest`. This is **identification**, not security: tokens travel in cleartext unless TLS is terminated at HAProxy (which is the deployment recommendation). No per-user passwords, no rotation, no revocation.
- Cost: acceptable for the scope; do not let a reader mistake this for an auth system.

### 4.19 Observability

- **Counters/gauges:** connections, frames in/out, bytes in/out, queued outbound bytes (total and max per connection), soft/hard limit events, WAL batch size, WAL fsync latency, bus publish/receive counts, Redis reconnects.
- **Latency:** Fixed log-scale histogram buckets (cheap, allocation-free in the hot path). Report p50/p99/p99.9 for MSG→ACK and MSG→DELIVER. Avoid coordinated omission in the load generator: schedule sends on a fixed clock and measure from the *intended* send time.
- **Loop lag:** A periodic timer measures `actual − expected` wake time. This is the single best "is the loop healthy" signal; if lag grows, something is blocking (I6).
- **Exposure:** Optional `STATS` command (see `PROTOCOL.md`) or a plain-text dump on `SIGUSR1`. No Prometheus dependency required.

---

## 5. Failure modes

| Failure | Behavior | Test |
|---------|----------|------|
| Client closes mid-frame | Partial buffer dropped, connection closed, no leak | M2 |
| Client RSTs | Logged at debug, connection closed | M2 |
| Client never reads | Soft limit pauses its reads; hard limit disconnects; other clients unaffected; RSS bounded | M3 |
| Client floods garbage | First framing error → fatal ERROR → close; no allocation by claimed length | M1 fuzz |
| Client silent | `IDLE_TIMEOUT` at 3× heartbeat | M5 |
| Client connects, never sends HELLO | `HELLO_TIMEOUT` at 5 s | M5 |
| `kill -9` mid-WAL-write | Recovery truncates torn tail, replays consistent prefix | M7 |
| Disk full / `ENOSPC` | WAL thread signals failure; node stops ACKing (and treats this as fatal for acceptance). No ACK without durability, ever. | M7 fault injection |
| Redis down | Local fanout continues; remote fanout lost; reconnect with backoff | M6, chaos |
| Redis partition (one-way) | As above; subscriber may not notice until the TCP connection dies, so a bus-level PING timeout is needed | chaos |
| Node killed | HAProxy routes new connections elsewhere; clients reconnect and re-JOIN; messages ACKed on the dead node remain in its WAL | chaos |
| SIGTERM under load | Drain per 4.17; every ACKed message in WAL | M8 |
| Second SIGTERM | Immediate non-zero exit; ACKed messages still safe (I10) | M8 |
| Loop stalls (bug) | Loop-lag alarm; idle timeouts may fire spuriously. Known amplification: a stall makes healthy clients look dead. | Review |

---

## 6. Testing strategy

| Layer | Technique |
|-------|-----------|
| Codec / decoder | Round-trip per frame type; byte-at-a-time feed; multi-frame chunk; truncated frames; **Hypothesis**: random frame sequences sliced at random boundaries decode identically; fuzzing with random bytes and mutated valid frames |
| Reactor / connections | 1000 concurrent connections; tiny `SO_SNDBUF` to force partial sends; mid-frame close; RST; idle CPU ≈ 0 |
| Backpressure | Non-reading client, assert bounded RSS, write-interest toggling, 100 healthy clients unaffected |
| Chat core | Pure, table-driven: join/leave/order/unknown command/message before HELLO/dedupe |
| Timers | Eviction at deadline, PING resets, 1000 timers don't degrade loop lag |
| RESP | Parser against replies fragmented at every offset; cross-check with `redis-py` |
| Bus | `InProcessBus` two-node tests first; then Redis; Alice on node 1 → Bob on node 2 through HAProxy; self-echo ignored |
| WAL | `kill -9` loops, torn-tail truncation, mid-file corruption detection, ACK-after-fsync assertion, replay equals pre-crash state |
| Shutdown | Under load: every ACKed message in WAL, clients got SHUTDOWN, exit ≤ deadline, code 0 |
| Chaos | Kill node, partition Redis, slow clients, malformed-frame fuzzing against a live server |

Testing principle: anything with a durability or ordering claim gets a test that tries to break it, not one that demonstrates the happy path.

---

## 7. Known limitations (stated up front)

1. No cross-node total ordering (4.11).
2. At-most-once to remote recipients; durable-but-unpublished window on crash (4.14).
3. No resume after reconnect; membership is not persisted.
4. No history API; the WAL is not a read path.
5. No WAL retention/compaction.
6. Auth is a shared-token identification scheme without in-process TLS.
7. Single loop thread per node: one core of useful work per node.
8. `node_id` is operator-assigned; duplicates will cause delivery to be silently dropped by the echo guard.

---

## 8. Benchmarks and results

> Fill this in from `bench/`; do not leave numbers here that weren't measured.

| Metric | Result | Setup |
|--------|--------|-------|
| Max concurrent connections (1 node) | _tbd_ | |
| Memory per idle connection | _tbd_ | |
| Msgs/s (1 node, N rooms, fanout F) | _tbd_ | |
| MSG→ACK p50 / p99 / p99.9 | _tbd_ | fsync device: _tbd_ |
| MSG→DELIVER p50 / p99 / p99.9 (same node) | _tbd_ | |
| MSG→DELIVER p50 / p99 / p99.9 (cross node) | _tbd_ | |
| Loop lag p99 at peak | _tbd_ | |
| What bounds throughput (profile) | _tbd_ | |

---

## 9. Milestone status

- [ ] M1 Codec + streaming decoder
- [ ] M2 Reactor + echo server
- [ ] M3 Buffers + backpressure
- [ ] M4 Chat core (single node)
- [ ] M5 Timers + heartbeats
- [ ] M6 Bus: in-process → RESP → Redis
- [ ] M7 WAL + writer thread
- [ ] M8 Graceful shutdown
- [ ] M9 Benchmarks, chaos, writeup

---

## 10. Further reading

- Kerrisk, *The Linux Programming Interface*, ch. 56–63 — sockets, non-blocking I/O, epoll, signals
- Kleppmann, *Designing Data-Intensive Applications*, ch. 3 and 11 — WAL/append-only storage; streams and brokers
- Redis `ae.c` / `networking.c` — a production reactor in ~500 lines of C
- Kegel, "The C10K Problem"
- TigerBeetle design docs — WAL, group commit, CRC, defensive design