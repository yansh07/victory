# chatengine Wire Protocol — v1

Status: draft, targets protocol version `1`.
Audience: anyone writing a client (the Python reference client, a Go/C load generator, a fuzzer).

Keywords MUST, MUST NOT, SHOULD, MAY are used in the RFC 2119 sense.

---

## 1. Transport and conventions

- Transport: TCP. One connection = one session. No multiplexing.
- TCP is a byte stream. Frame boundaries have no relationship to `send()`/`recv()` boundaries. A receiver MUST handle a frame split across any number of reads and any number of frames arriving in one read.
- All multi-byte integers are **unsigned, big-endian (network byte order)**.
- Python reference: `struct.Struct("!HBBBBII")` for the header.

### Primitive types

| Name   | Encoding                                               |
|--------|--------------------------------------------------------|
| `u8`   | 1 byte                                                 |
| `u16`  | 2 bytes                                                |
| `u32`  | 4 bytes                                                |
| `u64`  | 8 bytes                                                |
| `str`  | `u16` byte length, then that many bytes of UTF-8. No NUL bytes. Must be valid UTF-8. |
| `blob` | `u16` byte length, then that many opaque bytes         |

Strings and blobs are length-prefixed, never terminated. Receivers MUST reject invalid UTF-8 in a `str` with `MALFORMED_PAYLOAD`.

### Field constraints

| Field           | Constraint                                          |
|-----------------|-----------------------------------------------------|
| `room`          | 1–64 bytes, charset `[A-Za-z0-9._:-]`               |
| `user`          | 1–64 bytes, charset `[A-Za-z0-9._-]`                |
| `token`         | 0–256 bytes                                         |
| `body` (MSG)    | 0–16384 bytes, opaque (not required to be UTF-8)    |
| error `message` | 0–256 bytes                                         |

The restricted room charset is deliberate: room names become Redis channel names (`chat:room:<room>`), and a small charset removes an entire class of injection and parsing bugs.

---

## 2. Frame layout

Every frame is a fixed 14-byte header followed by `length` bytes of payload.

| Offset | Size | Field        | Description                                                        |
|-------:|-----:|--------------|--------------------------------------------------------------------|
| 0      | 2    | `magic`      | Constant `0xCE57`. First byte on the wire is `0xCE`.               |
| 2      | 1    | `version`    | Protocol version. Must equal `1`.                                  |
| 3      | 1    | `type`       | Frame type (section 3).                                            |
| 4      | 1    | `flags`      | Must be `0` in v1.                                                 |
| 5      | 1    | `reserved`   | Must be `0` in v1.                                                 |
| 6      | 4    | `request_id` | Client-chosen correlation ID. `0` for server-initiated frames.     |
| 10     | 4    | `length`     | Payload length in bytes, excluding the header. `0 <= length <= max_payload`. |

Total frame size = `14 + length`.

### Limits (defaults, advertised in HELLO_OK)

| Limit                    | Default  |
|--------------------------|---------:|
| `max_payload`            | 65536 B  |
| HELLO timeout            | 5 s      |
| Heartbeat interval range | 1 s – 60 s (server clamps) |
| Idle timeout             | 3 × negotiated heartbeat   |

### Header validation order (decoder contract)

The streaming decoder MUST validate in this order and MUST do so as soon as the relevant header bytes are available, **before buffering any payload**:

1. `magic` — mismatch → `BAD_MAGIC` (fatal)
2. `version` — not `1` → `UNSUPPORTED_VERSION` (fatal)
3. `flags`, `reserved` — non-zero → `MALFORMED_FRAME` (fatal)
4. `length` — greater than `max_payload` → `FRAME_TOO_LARGE` (fatal)
5. `type` — unknown → `UNKNOWN_TYPE` (**non-fatal**: the length is trustworthy, so the payload is skipped and the stream stays in sync)

Rationale: rejecting an oversized `length` before reading the payload means an attacker cannot make the server allocate memory by sending a header that claims 4 GiB. Failures 1–4 are fatal because after them the receiver can no longer trust where the next frame begins; there is no resynchronization in v1.

---

## 3. Frame types

| Code   | Name       | Direction | Purpose                                              |
|--------|------------|-----------|------------------------------------------------------|
| `0x01` | `HELLO`    | C → S     | Authenticate and open the session                    |
| `0x02` | `JOIN`     | C → S     | Join a room                                          |
| `0x03` | `LEAVE`    | C → S     | Leave a room                                         |
| `0x04` | `MSG`      | C → S     | Send a message to a room                             |
| `0x05` | `PING`     | both      | Liveness probe                                       |
| `0x06` | `PONG`     | both      | Reply to PING                                        |
| `0x07` | `ACK`      | S → C     | Positive response to a request                       |
| `0x08` | `ERROR`    | S → C     | Negative response or unsolicited error               |
| `0x09` | `SHUTDOWN` | both      | Graceful close announcement                          |
| `0x0A` | `DELIVER`  | S → C     | A room message delivered to a member                 |
| `0x0B` | `HELLO_OK` | S → C     | Handshake success, carries negotiated parameters     |
| `0x0C` | `STATS`    | C → S     | *Optional.* Request metrics snapshot                 |
| `0x0D` | `STATS_OK` | S → C     | *Optional.* UTF-8 `key=value\n` lines                |

`DELIVER`, `HELLO_OK`, and `STATS`/`STATS_OK` are additions beyond the minimum command list: without a server→client delivery frame and a handshake response there is nothing to carry the messages or the negotiated parameters.

---

## 4. Payloads

Every payload MUST be consumed exactly. Missing bytes **or trailing bytes** → `MALFORMED_PAYLOAD`. Strictness here is intentional: it keeps the decoder trivially fuzzable and prevents smuggling data in ignored tails.

### 4.1 HELLO (`0x01`, C → S)

| Field          | Type  | Notes                                      |
|----------------|-------|--------------------------------------------|
| `heartbeat_ms` | `u32` | Requested interval. `0` = server default. |
| `user`         | `str` | Display/identity name                      |
| `token`        | `str` | Auth token                                 |

Must be the first frame on a connection. Sent again → `ALREADY_HELLOED` (non-fatal).

### 4.2 HELLO_OK (`0x0B`, S → C)

| Field          | Type  | Notes                                           |
|----------------|-------|-------------------------------------------------|
| `session_id`   | `u64` | Unique per connection on this node              |
| `node_id`      | `u32` | Identifies the serving node                     |
| `heartbeat_ms` | `u32` | Negotiated (clamped) interval                   |
| `max_payload`  | `u32` | Server's limit; client MUST NOT exceed it       |

`request_id` echoes the HELLO's.

### 4.3 JOIN (`0x02`) / LEAVE (`0x03`), C → S

| Field  | Type  |
|--------|-------|
| `room` | `str` |

Success → `ACK` (`acked_type` = JOIN/LEAVE, `durable` = 0, `seq` = 0).
JOIN when already a member → `ALREADY_IN_ROOM`. LEAVE when not a member → `NOT_IN_ROOM`. Both non-fatal.
JOIN beyond the per-session room cap (default 64) → `ROOM_LIMIT`.

Membership is connection-local and in-memory. It does not survive disconnect (see DESIGN.md, known limitations).

### 4.4 MSG (`0x04`, C → S)

| Field           | Type   | Notes                                                              |
|-----------------|--------|--------------------------------------------------------------------|
| `room`          | `str`  | Sender MUST be a member, else `NOT_IN_ROOM`                        |
| `client_msg_id` | `u64`  | Client-chosen idempotency key, unique per `user`                   |
| `body`          | `blob` | ≤ 16384 bytes                                                      |

Server behavior:

1. Assign per-room sequence number on this node (section 6).
2. Append to the WAL; **no ACK is sent until the record is durable (fsynced)**.
3. After durability: send `ACK` to the sender, fan out `DELIVER` to local members (sender included), publish to the cluster bus.

**Idempotency:** if `(user, client_msg_id)` is within the server's dedupe window (default: last 1024 per user, rebuilt from the WAL on recovery), the server re-sends the original `ACK` and does **not** append or deliver again. Clients retry with the *same* `client_msg_id`.

### 4.5 ACK (`0x07`, S → C)

| Field        | Type  | Notes                                                        |
|--------------|-------|--------------------------------------------------------------|
| `acked_type` | `u8`  | Type code of the request being acknowledged                  |
| `durable`    | `u8`  | `1` iff the request's effects are fsynced in the WAL         |
| `seq`        | `u64` | For MSG: the assigned room sequence. Otherwise `0`.          |

`request_id` echoes the request. An ACK for MSG with `durable = 1` is the **only** durability promise in the protocol. It means "on this node's disk", not "delivered to anyone".

### 4.6 DELIVER (`0x0A`, S → C)

| Field           | Type   | Notes                                             |
|-----------------|--------|---------------------------------------------------|
| `room`          | `str`  |                                                   |
| `origin_node`   | `u32`  | Node that accepted the message from its sender    |
| `seq`           | `u64`  | Sequence assigned by `origin_node` for this room  |
| `sender`        | `str`  | `user` of the sender                              |
| `client_msg_id` | `u64`  | Echoed from MSG                                   |
| `body`          | `blob` |                                                   |

`request_id` is `0`.

Clients MAY dedupe on `(origin_node, room, seq)`; within a given `(origin_node, room)` pair, `seq` is strictly increasing. A gap in that sequence means a message was lost (pub/sub is at-most-once across nodes, see section 6).

### 4.7 PING / PONG (`0x05` / `0x06`)

| Field   | Type  |
|---------|-------|
| `nonce` | `u64` |

PONG echoes both `nonce` and `request_id`. Either side may initiate PING. Receiving **any** valid frame counts as liveness; PING exists for otherwise-silent connections.

### 4.8 ERROR (`0x08`, S → C)

| Field     | Type  | Notes                                                       |
|-----------|-------|-------------------------------------------------------------|
| `code`    | `u16` | Section 5                                                   |
| `fatal`   | `u8`  | `1` = server will flush this frame then close the connection |
| `message` | `str` | Human-readable, for logs only. Never parse it.              |

`request_id` echoes the offending request, or `0` if the error is not attributable to one (e.g. framing errors, idle timeout).

### 4.9 SHUTDOWN (`0x09`, both)

| Field         | Type  | Notes                                                       |
|---------------|-------|-------------------------------------------------------------|
| `reason`      | `u8`  | `0` = server shutting down, `1` = client leaving            |
| `deadline_ms` | `u32` | S → C: time the server will wait before force-closing. C → S: ignored. |

Server → client: begin closing; stop sending new MSG. Client → server: flush and close without error.

### 4.10 STATS / STATS_OK (optional)

`STATS` has an empty payload. The `STATS_OK` payload is raw UTF-8 text made of `key=value` lines. It has no inner length prefix: the frame header's `length` is the text length. Intended for debugging and bench harnesses; not part of the stability contract.

---

## 5. Error codes

| Code | Name                   | Fatal | When                                                       |
|-----:|------------------------|:-----:|------------------------------------------------------------|
| 1    | `BAD_MAGIC`            | yes   | Header magic mismatch                                      |
| 2    | `UNSUPPORTED_VERSION`  | yes   | `version != 1`                                             |
| 3    | `FRAME_TOO_LARGE`      | yes   | `length > max_payload`                                     |
| 4    | `MALFORMED_FRAME`      | yes   | Non-zero `flags` / `reserved`                              |
| 5    | `MALFORMED_PAYLOAD`    | no*   | Payload fails to parse / constraint violated               |
| 6    | `UNKNOWN_TYPE`         | no*   | Unrecognized `type` with valid length                      |
| 7    | `NOT_AUTHENTICATED`    | yes   | Any non-HELLO frame before HELLO                           |
| 8    | `AUTH_FAILED`          | yes   | Bad token                                                  |
| 9    | `ALREADY_HELLOED`      | no    | Second HELLO                                               |
| 10   | `NOT_IN_ROOM`          | no    | MSG/LEAVE for a room the session hasn't joined             |
| 11   | `ALREADY_IN_ROOM`      | no    | Duplicate JOIN                                             |
| 12   | `ROOM_LIMIT`           | no    | Per-session room cap exceeded                              |
| 13   | `RATE_LIMITED`         | no    | Token bucket exhausted (optional feature)                  |
| 14   | `SLOW_CONSUMER`        | yes   | Outbound buffer hit the hard limit                         |
| 15   | `IDLE_TIMEOUT`         | yes   | No inbound frames within the idle timeout                  |
| 16   | `HELLO_TIMEOUT`        | yes   | No HELLO within the handshake deadline                     |
| 17   | `SERVER_SHUTTING_DOWN` | no    | MSG/JOIN received while draining                           |
| 18   | `INTERNAL`             | yes   | Server bug. Should be a page-the-author event.             |

\* In the `HANDSHAKE` state every error is fatal regardless of this column.

**Rule of thumb:** an error is fatal exactly when the server can no longer trust stream framing or the peer is not allowed to continue. Errors where the frame boundary was valid leave the stream in sync and are survivable.

A server SHOULD send the `ERROR` frame and then close after flushing, but MAY drop it if the peer's buffer is already over the hard limit (it is already being disconnected for being slow).

---

## 6. Ordering and delivery semantics

| Guarantee | Statement |
|-----------|-----------|
| G1 — per-sender FIFO | Messages from one connection are sequenced in the order sent. |
| G2 — per-(node, room) order | For a fixed `(origin_node, room)`, `seq` is strictly increasing and gap-free in that node's WAL. |
| G3 — no cross-node total order | Messages from different origin nodes in the same room have no defined relative order. Two members on different nodes MAY observe different interleavings. |
| D1 — durable ACK | `ACK(MSG, durable=1)` ⇒ the message is fsynced on the origin node. |
| D2 — at-least-once to sender | A sender that does not receive the ACK retries with the same `client_msg_id`; the server dedupes. |
| D3 — at-most-once to recipients on other nodes | Cluster fanout uses Redis Pub/Sub; a node disconnected from Redis misses messages. Gaps are detectable via `seq` per `(origin_node, room)`. |
| D4 — local delivery after durability | A message is delivered to anyone only after it is durable on the origin node. |

Clients MUST NOT assume `DELIVER` and `ACK` for the same message arrive in any particular order relative to each other.

---

## 7. Connection state machine

```
        accept
          │
          ▼
   ┌─────────────┐  HELLO ok     ┌────────┐  SHUTDOWN (either side),   ┌──────────┐  flushed or   ┌────────┐
   │  HANDSHAKE  │ ────────────► │ ACTIVE │ ─────────────────────────► │ DRAINING │ ────────────► │ CLOSED │
   └─────────────┘               └────────┘  server drain begins       └──────────┘  deadline     └────────┘
          │                           │                                       │
          └── any error / timeout ────┴──── fatal ERROR / EOF / RST ──────────┴─────────────────────►  CLOSED
```

Frames accepted per state:

| State       | Accepted from client                            | Anything else |
|-------------|-------------------------------------------------|---------------|
| `HANDSHAKE` | `HELLO` only                                    | `NOT_AUTHENTICATED` (fatal) |
| `ACTIVE`    | `JOIN LEAVE MSG PING PONG SHUTDOWN STATS`       | `HELLO` → `ALREADY_HELLOED` |
| `DRAINING`  | `PING PONG SHUTDOWN`                            | `MSG`/`JOIN` → `SERVER_SHUTTING_DOWN` (non-fatal) |
| `CLOSED`    | nothing; socket is closed                       | —             |

Timers:

- **HELLO timeout:** 5 s from accept. Expiry → `HELLO_TIMEOUT` (fatal).
- **Idle timeout:** `3 × heartbeat_ms` since the last valid inbound frame. Expiry → `IDLE_TIMEOUT` (fatal).
- **Drain deadline:** `deadline_ms` from the SHUTDOWN frame. Expiry → close regardless of pending output.

---

## 8. Backpressure behavior visible to clients

Clients are expected to read continuously. The server keeps a bounded outbound queue per connection:

- Above the **soft limit** the server stops reading from that client (its requests stall; TCP flow control pushes back).
- Above the **hard limit** the server sends `ERROR(SLOW_CONSUMER, fatal)` (best effort) and closes.

Exact thresholds are server configuration, not protocol; see DESIGN.md. A well-behaved client that can't keep up should fail fast rather than rely on the server's patience.

---

## 9. Cluster bus envelope (inter-node, not client-facing)

Nodes share room traffic through Redis Pub/Sub.

- Channel: `chat:room:<room>`
- Message body (binary-safe RESP bulk string):

| Field     | Type    | Notes                                              |
|-----------|---------|----------------------------------------------------|
| `bus_ver` | `u8`    | `1`                                                |
| payload   | bytes   | Exactly a `DELIVER` payload (section 4.6)          |

Rules:

- A node publishes after the message is durable locally (D4).
- On receipt, a node parses the `DELIVER` payload; if `origin_node == self.node_id` it **drops** the message (it already delivered locally). This is the echo-loop guard.
- Otherwise it frames the payload as `DELIVER` (`request_id = 0`) and queues it to local members of `room`.
- A node subscribes to a room's channel when its first local member joins and unsubscribes when the last leaves.
- `node_id` MUST be unique per node; it is configured, not random.

---

## 10. Test vectors

Whitespace is for readability only.

**PING**, `request_id = 1`, `nonce = 0x0102030405060708`:

```
CE57 01 05 00 00 00000001 00000008 0102030405060708
```
(22 bytes: 14-byte header + 8-byte payload)

**JOIN** room `"general"`, `request_id = 2`:

```
CE57 01 02 00 00 00000002 00000009 0007 67656E6572616C
```
(23 bytes: 14-byte header + 2-byte length + 7 bytes of `general`)

**Decoder cases every implementation must pass:**

| Input                                          | Expected                                   |
|------------------------------------------------|--------------------------------------------|
| PING fed one byte at a time                    | One PING frame after the 22nd byte        |
| Three PINGs in one chunk                       | Three frames, in order                     |
| PING truncated at any byte offset              | No output, no exception, remaining buffered |
| Header with `magic = 0x0000`                   | `BAD_MAGIC`, fatal                         |
| Header with `version = 2`                      | `UNSUPPORTED_VERSION`, fatal               |
| Header with `length = 0xFFFFFFFF`              | `FRAME_TOO_LARGE` **without** buffering payload |
| JOIN with `room` length 7 but 8 payload bytes  | `MALFORMED_PAYLOAD` (trailing byte)        |
| JOIN room `"bad room"`                         | `MALFORMED_PAYLOAD` (charset)              |
| Unknown type `0x7F` with `length = 3`          | `UNKNOWN_TYPE` non-fatal, next frame decodes normally |

Property: for any sequence of valid frames, concatenating their encodings and splitting at arbitrary byte boundaries MUST decode to the same sequence.

---

## 11. Versioning policy

- `version` changes only for incompatible wire changes. v1 peers reject anything else.
- Within v1, additions are limited to new frame types (older peers answer `UNKNOWN_TYPE`, non-fatal) and new `ERROR` codes. Existing payload layouts are frozen.
- Features that need new fields in existing frames (e.g. resume-from-sequence in HELLO) require `version = 2`. `flags` bits are reserved for this purpose and are rejected today so that nobody ships clients that set them by accident.