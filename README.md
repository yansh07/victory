# Victory Engine

## 🚀 Core Engineering Manifest

**A high-performance, distributed messaging engine built in synchronous Python using raw Linux epoll multiplexing, a custom streaming wire protocol, and a durable transactional storage engine with zero dependencies.**

- **Runtime:** CPython 3.11+, standard library only. Linux uses native `select.epoll()` with level-triggered readiness; `selectors` provides the macOS/BSD development fallback.
- **Ownership:** exactly two engine threads: one reactor thread owns connections, sessions, rooms, timers, and cluster sockets; one storage thread owns WAL appends and durability operations.
- **Transactional unit:** one accepted message append. A durability completion gates its ACK, local delivery, and cluster publication.
- **External infrastructure:** Redis enables multi-node fanout; HAProxy provides optional L4 balancing and TLS termination. Neither is a Python package dependency.
- **Development dependencies:** `pytest`, Hypothesis, and an optional `redis-py` test oracle remain outside the runtime core.

**Banned from the runtime core:**

- `asyncio`, `async`/`await`, and `uvloop`.
- `socketserver`, Twisted, and networking/application frameworks.
- Blocking socket operations, disk operations, and application-lock waits on the reactor thread.
- Third-party Redis clients or protocol libraries that hide the transport state machines.

Architecture decisions and costs live in [DESIGN.md](DESIGN.md). The normative wire contract lives in [docs/PROTOCOL.md](docs/PROTOCOL.md).

## 🔥 The Architectural Moat

### Zero-copy frame parsing with bounded stream state

- **Explicit decoder FSM:** `WAIT_HEADER → WAIT_PAYLOAD → emit → WAIT_HEADER`. TCP fragmentation and frame coalescing do not change command boundaries.
- **Shared input storage:** one loop-wide 64 KiB `bytearray`, filled with `recv_into()`. `struct.unpack_from()` and `memoryview` offsets parse complete frames in place; fragmented tails move into bounded connection-local storage.
- **Controlled compaction:** advance a read offset rather than deleting bytes from the front. Compact after the consumed prefix exceeds half the buffer capacity or the buffer empties. Release views before resizing a `bytearray`.
- **Explicit copy boundary:** zero-copy describes parser access and partial-write slicing. It does not imply a kernel-to-application zero-copy transport or permanently borrowed payload storage.

The v1 header is **14 bytes**, encoded as `!HBBBBII`:

```text
magic:u16 | version:u8 | type:u8 | flags:u8 | reserved:u8 | request_id:u32 | length:u32
```

Header validation follows one fixed order **before payload buffering**:

1. `magic == 0xCE57`.
2. `version == 1`.
3. `flags == 0` and `reserved == 0`.
4. `length <= 65536` bytes.
5. Recognized frame type.

This ordering defends **I7**: an untrusted length cannot drive proportional allocation before validation. Framing failures terminate the stream. The decoder reports an unknown type non-fatally and skips its validated payload to preserve alignment; session policy still applies. Command payloads must consume every byte: truncation and trailing data produce `MALFORMED_PAYLOAD`. The separate MSG body limit is **16384 bytes**.

### Flow control: hysteresis plus slow-consumer eviction

Outbound staging uses a `collections.deque` of `memoryview` chunks and an explicit logical-byte counter. A short `send()` advances the head view; it does not copy the unsent suffix.

| Threshold | Default | Reactor action |
|---|---:|---|
| Soft/high watermark | 256 KiB | Remove `EPOLLIN`; stop consuming that client's requests. |
| Low watermark | 64 KiB | Restore `EPOLLIN` after the queue drains below the floor. |
| Hard limit | 1 MiB | Best-effort fatal `SLOW_CONSUMER`, then connection teardown. |

Pausing reads lets the kernel receive buffer fill and TCP flow control push pressure back to the sender. The gap between high and low watermarks prevents interest-mask oscillation.

Fanout requires the hard limit: pausing a slow subscriber's reads cannot stop other publishers from generating output for it. Eviction bounds its retained queue and protects healthy clients without silently dropping messages from an established session.

**Memory accounting is explicit:** for a bounded connection count `N`, per-connection logical output is bounded by approximately `N × 1 MiB`. Fanout shares encoded frame bytes; inbound storage, WAL queues, Python objects, and kernel socket buffers are additional costs. A separate aggregate outbound quota remains a documented extension.

### Transactional storage: group commit behind a durability fence

The reactor stages WAL work and continues servicing sockets. The storage worker coalesces encoded records into a write buffer, completes short writes and interrupted syscalls, then performs **one data-file `fsync()` per commit batch**. Records arriving during that operation form subsequent batches; the default design adds no artificial batching delay.

```text
validated MSG → WAL request deque → append + fsync → completion deque
                                                     ↓
                                      ACK / local DELIVER / bus publish
```

- **I1:** `ACK(MSG, durable=1)` implies the corresponding record has been fsynced on the origin node.
- **I2:** local and remote delivery become eligible only after origin-node durability.
- **Failure containment:** an append or fsync failure stops durable acknowledgments and further message acceptance; a failed batch cannot become a successful completion.

Segments are append-only, default to **64 MiB**, and use `wal-<8-digit-index>.log` names:

```text
segment header: magic(4) | version(1) | first_lsn(8)
record:         crc32(4) | length(4) | lsn(8) | type(1) | payload(length - 9)
CRC coverage:   length | lsn | type | payload
```

Multi-byte fields are big-endian. Checksums use IEEE CRC-32 through `zlib.crc32`. Segment creation additionally syncs directory metadata so a crash cannot discard a newly created segment's directory entry; those metadata syncs are separate from the batch's data fsync.

**Recovery preserves a verified prefix — I4:**

- Short record or bad CRC at the terminal tail of the final segment: truncate to the last verified record boundary.
- Corruption in a historical segment, or valid records following damaged data in the final segment: abort startup.
- Replay never applies records beyond the first damaged boundary. Valid replay rebuilds room sequence state and the deduplication window.

### Single-writer concurrency and the self-pipe trick

- **One owner per mutable state domain.** The storage worker receives records, not client sockets or permission to emit ACKs.
- **Atomic queue operations:** request and completion mailboxes use CPython's atomic `collections.deque.append()` / `popleft()` operations with fixed producer/consumer ownership. Compound state transitions remain with their owning thread.
- **Readiness-driven completion:** after fsync, the worker publishes a completion and writes a one-byte hint to a non-blocking socketpair registered with epoll. The reactor drains both the notification descriptor and completion deque before executing resulting intents.
- **No application locks on the reactor hot path.** Durability completion becomes ordinary descriptor readiness rather than a sleeping wait or periodic queue poll. The completion deque is authoritative; redundant notification bytes are harmless.

The same ownership discipline governs network progress:

| Mechanism | Contract |
|---|---|
| Accept fairness | Accept until `EAGAIN`, capped at 64 accepts per pass. |
| Read fairness | Consume at most 64 KiB per connection per pass. |
| Write readiness | Enable `EPOLLOUT` only while output exists; remove it when drained. |
| Connection failures | Retry `EINTR`; handle `EAGAIN` as temporary; tear down peers on `ECONNRESET`, `EPIPE`, or `ETIMEDOUT`. |
| Timers | Monotonic `heapq` deadlines determine poll timeout; heartbeat activity updates timestamps and expiration checks re-arm lazily. |

## 📂 Precision System Layout

```text
victory/
├── DESIGN.md
├── SYSTEM_RULES.md
├── docs/
│   └── PROTOCOL.md
├── src/victory/
│   ├── protocol/
│   │   ├── frame.py           # Frames, type codes, protocol failures
│   │   ├── codec.py           # Strict binary payload encoding/decoding
│   │   └── decoder.py         # Fragmented-stream state machine
│   ├── net/
│   │   ├── backends.py        # Native epoll and development fallback
│   │   ├── reactor.py         # Readiness dispatch and fairness budgets
│   │   ├── connection.py      # Buffer ownership, partial writes, watermarks
│   │   └── timers.py          # Deadlines and lazy heartbeat expiration
│   ├── core/
│   │   ├── session.py         # Authentication and session lifecycle
│   │   ├── rooms.py           # Membership and origin-local sequencing
│   │   └── router.py          # Command validation, dedupe, action intents
│   ├── cluster/
│   │   ├── bus.py             # ClusterBus contract and InProcessBus
│   │   ├── resp.py            # Streaming RESP2 encoder/parser
│   │   └── redis_bus.py       # Publisher/subscriber sockets and reconnect
│   ├── storage/
│   │   ├── wal.py             # Record framing, segments, recovery
│   │   └── writer_thread.py   # Group commit and durability completions
│   └── lifecycle/
│       └── shutdown.py        # Signal wakeup and bounded draining
├── tests/
│   ├── unit/                 # Codec, state, buffers, timers, bus, WAL
│   └── integration/          # TCP behavior, durability, process signals
└── bench/                    # Benchmark workloads and result records
```

`core/` consumes decoded frames and returns structured intents such as `AppendWalAction` and `EnqueueClientBufferAction`, keeping business logic completely socket-free and testable without epoll, disk I/O, or Redis.

## 📊 Distributed Topologies & Wire Guarantees

| Topology | Ingress | Fanout | Durability boundary |
|---|---|---|---|
| Single node | Direct TCP | Local delivery; `InProcessBus` for isolated bus tests | That node's WAL |
| Multiple nodes | HAProxy L4 balancing, with optional TLS termination | Redis Pub/Sub between independent nodes | Each message's origin-node WAL |

### Dual-socket RESP2 cluster bus

- Each node owns **two raw, non-blocking Redis sockets**: one publisher and one dedicated subscriber. Subscription traffic cannot consume the publisher's command channel.
- The RESP2 parser incrementally decodes arrays and binary-safe bulk strings across arbitrary read boundaries.
- Room channels are `chat:room:<room>`; the bus envelope is `bus_ver:u8 = 1` followed by the exact `DELIVER` payload.
- Subscribe when the first local room member joins; unsubscribe when the last leaves.
- Reconnect uses exponential backoff with jitter and restores subscriptions for rooms with local members. Local delivery continues during Redis outages; remote traffic can be lost.

### Echo-loop suppression — I9

A subscriber validates the envelope, extracts `origin_node`, and drops the message when `origin_node == self.node_id` **before local fanout**. Every node therefore requires a unique configured ID. A remote message retains its original node and sequence identity.

### Ordering and delivery contract

| Guarantee | Supported | Exact scope |
|---|---|---|
| Per-sender FIFO — G1 | **Yes** | Messages from one connection are sequenced in send order. |
| Per-(node, room) monotonic sequence — G2 | **Yes** | `u64 seq` is strictly increasing and gap-free in that origin's room WAL. Remote receivers can observe gaps after transport loss. |
| Total cross-node order — G3 | **No** | Concurrent origins can produce different interleavings at different recipients. A global sequencer or consensus layer is outside v1 scope. |
| Durable message ACK — I1 / D1 | **Yes** | Local fsync on the origin node; no replica quorum or recipient-delivery promise. |
| Retry deduplication — I8 / D2 | **Bounded** | Last 1024 entries per user, keyed by `(user, client_msg_id)` and rebuilt from WAL replay. A hit reuses the ACK without another append or fanout. |
| Cross-node delivery — D3 | **At most once** | Redis Pub/Sub provides no replay for disconnected subscribers. |
| Delivery after durability — I2 / D4 | **Yes** | Both local delivery and cluster publication follow origin-node fsync. |

`ACK` and `DELIVER` have no specified relative arrival order. Clients retry uncertain sends with the same `client_msg_id`; receivers can deduplicate messages by `(origin_node, room, seq)`.

**The durable-but-unpublished window is explicit:** a crash after fsync but before Redis publication can leave an ACKed message absent from remote nodes. Sender deduplication does not republish it. Durable remote replay requires an additional mechanism such as Redis Streams or WAL-tail republication with receiver deduplication.

Other v1 boundaries: reconnect requires a new `HELLO` and room joins; membership is volatile; the WAL is not a history API and has no retention/compaction policy. Authentication uses configured tokens and `hmac.compare_digest`; transport confidentiality belongs at the TLS terminator.

## 🧪 Defensive Testing & Chaos Engineering

The validation contract is organized around failure boundaries and invariants:

| Boundary | Injection | Required assertion |
|---|---|---|
| TCP stream framing | Hypothesis-generated frame sequences and random split points; deterministic one-byte feeds | Exact FIFO reconstruction; no early emission or attacker-length allocation — I7. |
| Partial writes | Request `SO_SNDBUF = 1024` on server/client sockets; send large frames through constrained buffers | Resume short writes and `EAGAIN` using sliced views; preserve every byte. |
| Slow consumers | Stall one reader while healthy clients continue | High/low read-interest transitions, hard-limit eviction, bounded retained output — I5. |
| Reactor fairness | Burst accepts, competing senders, EOF/RST mid-frame, idle sockets | Respect accept/read budgets; isolate failed peers; block in the kernel when idle. |
| Pure chat state | Commands before HELLO, repeated HELLO, room sequencing, duplicate message IDs | Authentication barrier, gap-free origin-room WAL order, no duplicate append or fanout — I3/I8. |
| Timers and cluster bus | Fake monotonic time, fragmented RESP2, Redis teardown/reconnect, self-origin publications | Correct lazy expiration, restored subscriptions, no self-redelivery — I9. |
| Durability fence | Hold fsync behind a barrier; inject write/fsync failure and `ENOSPC` | Zero durable ACKs before successful completion; failed commits never release success — I1/I2. |
| Crash recovery | Torn terminal records, CRC mutation, historical corruption, process termination | Repair only a terminal tail; abort on interior corruption; replay a verified prefix — I4. |
| Graceful shutdown | Five active TCP clients, pending WAL work, real `SIGTERM`/`SIGINT` | Stop accepts, deliver SHUTDOWN, drain output and WAL, exit within the deadline; every observed durable ACK has a matching WAL record — I10. |
| Operator override | A second interrupt while a commit is blocked | Immediate process exit with code 1; previously ACKed messages remain in the origin WAL — I10. |

### Shutdown is a state machine

`RUNNING → DRAINING → FLUSHING → EXIT`

1. The signal handler records a flag and writes one byte to a non-blocking wakeup descriptor. Application mutations and teardown run on the reactor thread.
2. DRAINING removes listener interest, closes listeners, broadcasts `SHUTDOWN(reason=0, deadline_ms)`, and rejects new MSG/JOIN with non-fatal `SERVER_SHUTTING_DOWN`.
3. FLUSHING finishes accepted WAL work, consumes durability completions, and drains the resulting outbound queues.
4. Successful completion exits with code 0. The configured deadline bounds draining; a second interrupt forces code 1.

The guarantee covers **already durably ACKed messages**. Unacknowledged in-flight messages remain retryable; it does not promise successful delivery to every remote subscriber.

### Run validation

With development dependencies installed:

```sh
python -m pytest tests/unit tests/integration
```

Redis-backed integration cases additionally require Redis; isolated codec, core, WAL, and `InProcessBus` tests do not.

### Performance evidence

Watermarks, budgets, and segment sizes are configuration defaults, not benchmark results. Throughput and tail-latency claims belong in `bench/` with the CPython version, workload, fanout, payload size, storage device, fsync latency, RSS, and loop-lag measurements. No unmeasured throughput or cross-language speedup is claimed.