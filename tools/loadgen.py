#!/usr/bin/env python3
from __future__ import annotations

import argparse
import errno
import json
import math
import os
import re
import secrets
import selectors
import socket
import struct
import sys
import time
from array import array
from collections import deque
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

HEADER = struct.Struct("!HBBBBII")
ACK = struct.Struct("!BBQ")
MAX_PAYLOAD = 65536
MAX_BODY = 16384
READ_BUDGET = 65536
MAX_TX_BYTES = 1024 * 1024
UINT64_MAX = (1 << 64) - 1
ROOM_PATTERN = re.compile(r"[A-Za-z0-9._:-]{1,64}\Z")
USER_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")


class WireError(RuntimeError):
    """A transport or protocol contract failed."""


@dataclass(frozen=True, slots=True)
class WireFrame:
    kind: int
    request_id: int
    payload: bytes


def encode_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    if len(encoded) > 65535 or b"\x00" in encoded:
        raise ValueError("invalid protocol string")
    return struct.pack("!H", len(encoded)) + encoded


def encode_frame(kind: int, request_id: int, payload: bytes) -> bytes:
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("frame payload is too large")
    return HEADER.pack(
        0xCE57, 1, kind, 0, 0, request_id, len(payload)
    ) + payload


def encode_message(room: str, message_id: int, body: bytes) -> bytes:
    if not ROOM_PATTERN.fullmatch(room) or len(body) > MAX_BODY:
        raise ValueError("invalid room or message body")
    return (
        encode_string(room)
        + struct.pack("!QH", message_id, len(body))
        + body
    )


def decode_ack(frame: WireFrame) -> tuple[int, int, int]:
    if frame.kind != 7 or len(frame.payload) != ACK.size:
        raise WireError("malformed ACK")
    kind, durable, seq = ACK.unpack(frame.payload)
    if durable not in (0, 1):
        raise WireError("invalid ACK durability flag")
    return kind, durable, seq


def decode_error(frame: WireFrame) -> tuple[int, bool, str]:
    if len(frame.payload) < 5:
        raise WireError("truncated ERROR")
    code, fatal, length = struct.unpack_from("!HBH", frame.payload)
    if fatal not in (0, 1) or length > 256 or len(frame.payload) != length + 5:
        raise WireError("malformed ERROR")
    try:
        message = frame.payload[5:].decode("utf-8")
    except UnicodeError as exc:
        raise WireError("invalid ERROR text") from exc
    if "\x00" in message:
        raise WireError("NUL in ERROR text")
    return code, bool(fatal), message


class FrameStream:
    __slots__ = ("buffer", "offset")

    def __init__(self) -> None:
        self.buffer = bytearray()
        self.offset = 0

    @property
    def buffered_bytes(self) -> int:
        return len(self.buffer) - self.offset

    def feed(self, data: bytes | memoryview) -> list[WireFrame]:
        limit = MAX_PAYLOAD + HEADER.size + READ_BUDGET
        if self.buffered_bytes + len(data) > limit:
            raise WireError("receive buffer limit exceeded")

        self.buffer.extend(data)
        frames: list[WireFrame] = []

        while len(self.buffer) - self.offset >= HEADER.size:
            (
                magic,
                version,
                kind,
                flags,
                reserved,
                request_id,
                length,
            ) = HEADER.unpack_from(self.buffer, self.offset)

            if magic != 0xCE57:
                raise WireError("BAD_MAGIC")
            if version != 1:
                raise WireError("UNSUPPORTED_VERSION")
            if flags or reserved:
                raise WireError("MALFORMED_FRAME")
            if length > MAX_PAYLOAD:
                raise WireError("FRAME_TOO_LARGE")

            end = self.offset + HEADER.size + length
            if end > len(self.buffer):
                break

            with memoryview(self.buffer)[
                self.offset + HEADER.size:end
            ] as view:
                payload = bytes(view)

            frames.append(WireFrame(kind, request_id, payload))
            self.offset = end

        if self.offset == len(self.buffer):
            self.buffer.clear()
            self.offset = 0
        elif self.offset > len(self.buffer) // 2:
            del self.buffer[:self.offset]
            self.offset = 0

        return frames


class Phase(IntEnum):
    HELLO = 0
    JOIN = 1
    ACTIVE = 2
    CLOSING = 3
    CLOSED = 4


@dataclass(slots=True)
class _Chunk:
    data: memoryview
    kind: int
    request_id: int


def resolve_address(host: str, port: int) -> tuple[str, int]:
    entries = socket.getaddrinfo(
        host, port, socket.AF_INET, socket.SOCK_STREAM
    )
    if not entries:
        raise WireError("host has no IPv4 address")
    return entries[0][4][0], port


class ProtocolClient:
    def __init__(
        self,
        address: tuple[str, int],
        user: str,
        token: str,
        room: str | None,
        *,
        heartbeat_ms: int = 10000,
        receive_buffer: int | None = None,
    ) -> None:
        if not USER_PATTERN.fullmatch(user):
            raise ValueError("invalid protocol user")
        if room is not None and not ROOM_PATTERN.fullmatch(room):
            raise ValueError("invalid protocol room")
        if not 1 <= len(token.encode("utf-8")) <= 256 or "\x00" in token:
            raise ValueError("invalid authentication token")

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setblocking(False)
        self.phase = Phase.HELLO
        self.room = room
        self.decoder = FrameStream()
        self.outgoing: deque[_Chunk] = deque()
        self.queued_bytes = 0
        self.connecting = True
        self.eof = False
        self.read_calls = 0
        self.node_id: int | None = None
        self.session_id: int | None = None
        self.heartbeat_ms = heartbeat_ms
        self.next_ping_ns = time.monotonic_ns() + heartbeat_ms * 500000
        self.pending_ping: int | None = None

        try:
            if receive_buffer is not None:
                self.socket.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_RCVBUF,
                    receive_buffer,
                )

            error = self.socket.connect_ex(address)
            if error not in (
                0,
                errno.EINPROGRESS,
                errno.EWOULDBLOCK,
                errno.EALREADY,
                errno.EINTR,
            ):
                raise OSError(error, os.strerror(error))

            self.connecting = error != 0
            hello = (
                struct.pack("!I", heartbeat_ms)
                + encode_string(user)
                + encode_string(token)
            )
            self.queue_frame(1, 1, hello)
        except BaseException:
            self.socket.close()
            raise

    @property
    def interest(self) -> int:
        return selectors.EVENT_READ | (
            selectors.EVENT_WRITE
            if self.connecting or self.outgoing
            else 0
        )

    def queue_frame(
        self, kind: int, request_id: int, payload: bytes
    ) -> None:
        packet = encode_frame(kind, request_id, payload)
        if (
            self.phase == Phase.CLOSED
            or self.queued_bytes + len(packet) > MAX_TX_BYTES
        ):
            raise WireError("client outbound queue limit exceeded")

        self.outgoing.append(
            _Chunk(memoryview(packet), kind, request_id)
        )
        self.queued_bytes += len(packet)

    def flush(self) -> list[tuple[int, int]]:
        if self.connecting:
            error = self.socket.getsockopt(
                socket.SOL_SOCKET, socket.SO_ERROR
            )
            if error:
                raise OSError(error, os.strerror(error))
            self.connecting = False

        sent: list[tuple[int, int]] = []
        budget = READ_BUDGET

        while self.outgoing and budget:
            head = self.outgoing[0]
            try:
                count = self.socket.send(head.data[:budget])
            except InterruptedError:
                continue
            except BlockingIOError:
                break

            if count <= 0:
                raise WireError("send made no progress")

            self.queued_bytes -= count
            budget -= count

            if count == len(head.data):
                self.outgoing.popleft()
                now = time.monotonic_ns()
                self.next_ping_ns = now + self.heartbeat_ms * 500000
                if head.kind == 4:
                    sent.append((head.request_id, now))
            else:
                head.data = head.data[count:]

        return sent

    def read_frames(self, scratch: bytearray) -> list[WireFrame]:
        frames: list[WireFrame] = []
        budget = min(READ_BUDGET, len(scratch))

        while budget:
            try:
                self.read_calls += 1
                count = self.socket.recv_into(scratch, budget)
            except InterruptedError:
                continue
            except BlockingIOError:
                break

            if not count:
                self.eof = True
                if self.decoder.buffered_bytes:
                    raise WireError("EOF inside a frame")
                break

            budget -= count
            with memoryview(scratch)[:count] as view:
                frames.extend(self.decoder.feed(view))

        return frames

    def handle_control(self, frame: WireFrame) -> bool:
        if frame.kind == 11:
            if (
                self.phase != Phase.HELLO
                or frame.request_id != 1
                or len(frame.payload) != 20
            ):
                raise WireError("unexpected HELLO_OK")

            session, node, heartbeat, maximum = struct.unpack(
                "!QIII", frame.payload
            )
            if (
                not session
                or not 1000 <= heartbeat <= 60000
                or maximum != MAX_PAYLOAD
            ):
                raise WireError("invalid HELLO_OK parameters")

            self.session_id, self.node_id = session, node
            self.heartbeat_ms = heartbeat
            self.next_ping_ns = (
                time.monotonic_ns() + heartbeat * 500000
            )

            if self.room is None:
                self.phase = Phase.ACTIVE
            else:
                self.queue_frame(2, 2, encode_string(self.room))
                self.phase = Phase.JOIN
            return True

        if frame.kind == 7:
            kind, durable, seq = decode_ack(frame)
            if kind != 2:
                return False
            if (
                self.phase != Phase.JOIN
                or (frame.request_id, durable, seq) != (2, 0, 0)
            ):
                raise WireError("unexpected JOIN ACK")
            self.phase = Phase.ACTIVE
            return True

        if frame.kind == 5:
            if len(frame.payload) != 8:
                raise WireError("malformed PING")
            self.queue_frame(6, frame.request_id, frame.payload)
            return True

        if frame.kind == 6:
            if len(frame.payload) != 8:
                raise WireError("malformed PONG")
            nonce = struct.unpack("!Q", frame.payload)[0]
            if frame.request_id != 3 or nonce != self.pending_ping:
                raise WireError("unexpected PONG")
            self.pending_ping = None
            return True

        if frame.kind == 8:
            code, fatal, message = decode_error(frame)
            raise WireError(
                f"server ERROR code={code} fatal={int(fatal)}: {message}"
            )

        if frame.kind == 9:
            if len(frame.payload) != 5:
                raise WireError("malformed SHUTDOWN")
            if self.phase == Phase.CLOSING:
                return True
            raise WireError("server shutdown during operation")

        if frame.kind == 10:
            return True

        return False

    def heartbeat(self, now_ns: int) -> None:
        if (
            self.phase == Phase.ACTIVE
            and self.pending_ping is None
            and now_ns >= self.next_ping_ns
        ):
            self.pending_ping = now_ns & UINT64_MAX
            self.queue_frame(
                5, 3, struct.pack("!Q", self.pending_ping)
            )
            self.next_ping_ns = now_ns + self.heartbeat_ms * 500000

    def begin_close(self) -> None:
        if self.phase == Phase.ACTIVE:
            self.queue_frame(9, 5, struct.pack("!BI", 1, 0))
            self.phase = Phase.CLOSING

    def close(self) -> None:
        if self.phase != Phase.CLOSED:
            self.socket.close()
            self.outgoing.clear()
            self.queued_bytes = 0
            self.phase = Phase.CLOSED


def handshake(
    address: tuple[str, int],
    user: str,
    token: str,
    room: str | None,
    *,
    timeout: float = 5.0,
    heartbeat_ms: int = 10000,
    receive_buffer: int | None = None,
) -> ProtocolClient:
    peer = ProtocolClient(
        address,
        user,
        token,
        room,
        heartbeat_ms=heartbeat_ms,
        receive_buffer=receive_buffer,
    )
    scratch = bytearray(READ_BUDGET)
    deadline = time.monotonic() + timeout

    try:
        with selectors.DefaultSelector() as selector:
            selector.register(peer.socket, peer.interest)

            while peer.phase != Phase.ACTIVE:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise WireError("handshake timed out")

                for key, mask in selector.select(remaining):
                    if mask & selectors.EVENT_WRITE:
                        peer.flush()

                    if mask & selectors.EVENT_READ:
                        for frame in peer.read_frames(scratch):
                            if not peer.handle_control(frame):
                                raise WireError(
                                    "unexpected handshake frame"
                                )
                        if peer.eof:
                            raise WireError(
                                "connection closed during handshake"
                            )

                    selector.modify(peer.socket, peer.interest)

        return peer
    except BaseException:
        peer.close()
        raise


class LatencyHistogram:
    """Fixed memory with 32 logarithmic sub-buckets per power of two."""

    def __init__(self) -> None:
        self.buckets = array("Q", [0]) * (64 * 32 + 1)
        self.count = 0
        self.total = 0
        self.minimum = UINT64_MAX
        self.maximum = 0

    def observe(self, value: int) -> None:
        value = min(max(0, value), UINT64_MAX)
        if value:
            power = value.bit_length() - 1
            base = 1 << power
            index = 1 + power * 32 + ((value - base) * 32 // base)
        else:
            index = 0

        self.buckets[index] += 1
        self.count += 1
        self.total += value
        self.minimum = min(self.minimum, value)
        self.maximum = max(self.maximum, value)

    def percentile(
        self, numerator: int, denominator: int = 100
    ) -> int:
        if not self.count:
            return 0

        rank = (
            self.count * numerator + denominator - 1
        ) // denominator
        cumulative = 0

        for index, count in enumerate(self.buckets):
            cumulative += count
            if cumulative >= rank:
                if not index:
                    return 0
                power, sub = divmod(index - 1, 32)
                base = 1 << power
                upper = (
                    base + (base * (sub + 1) + 31) // 32 - 1
                )
                return min(upper, self.maximum)

        return self.maximum

    def summary(self) -> dict[str, int | float]:
        return {
            "count": self.count,
            "min_us": self.minimum / 1000 if self.count else 0,
            "mean_us": (
                self.total / self.count / 1000
                if self.count else 0
            ),
            "p50_upper_us": self.percentile(50) / 1000,
            "p95_upper_us": self.percentile(95) / 1000,
            "p99_upper_us": self.percentile(99) / 1000,
            "p999_upper_us": self.percentile(999, 1000) / 1000,
            "max_us": self.maximum / 1000,
        }


class _Schedule:
    """An indexed minimum heap with one entry per connection."""

    def __init__(self, size: int) -> None:
        self.heap: list[int] = []
        self.position = [-1] * size
        self.deadline = [0] * size

    def _less(self, left: int, right: int) -> bool:
        a, b = self.heap[left], self.heap[right]
        left_deadline = self.deadline[a]
        right_deadline = self.deadline[b]
        return (
            left_deadline < right_deadline
            or (left_deadline == right_deadline and a < b)
        )

    def _swap(self, left: int, right: int) -> None:
        self.heap[left], self.heap[right] = (
            self.heap[right], self.heap[left]
        )
        self.position[self.heap[left]] = left
        self.position[self.heap[right]] = right

    def _repair(self, position: int) -> None:
        while position and self._less(
            position, (position - 1) // 2
        ):
            parent = (position - 1) // 2
            self._swap(position, parent)
            position = parent

        while True:
            left = position * 2 + 1
            if left >= len(self.heap):
                return

            right = left + 1
            child = (
                right
                if right < len(self.heap) and self._less(right, left)
                else left
            )
            if not self._less(child, position):
                return

            self._swap(position, child)
            position = child

    def set(self, index: int, deadline: int) -> None:
        self.deadline[index] = deadline
        position = self.position[index]
        if position < 0:
            position = len(self.heap)
            self.position[index] = position
            self.heap.append(index)
        self._repair(position)

    def remove(self, index: int) -> None:
        position = self.position[index]
        if position < 0:
            return

        last = self.heap.pop()
        self.position[index] = -1
        if position < len(self.heap):
            self.heap[position] = last
            self.position[last] = position
            self._repair(position)

    def first(self) -> int | None:
        return self.deadline[self.heap[0]] if self.heap else None

    def pop_due(self, now: int) -> int | None:
        if not self.heap or self.deadline[self.heap[0]] > now:
            return None
        index = self.heap[0]
        self.remove(index)
        return index


@dataclass(slots=True)
class _Pending:
    intended_ns: int
    sent_ns: int = 0


@dataclass(slots=True)
class _Client:
    index: int
    peer: ProtocolClient | None = None
    resolved: bool = False
    registered: bool = False
    fd: int = -1
    work_done: bool = False
    failed: bool = False
    next_message: int = 1
    acknowledged: int = 0
    handshake_deadline: int = 0
    pending: dict[int, _Pending] = field(default_factory=dict)


class LoadGenerator:
    def __init__(
        self, args: argparse.Namespace, token: str
    ) -> None:
        self.args = args
        self.address = resolve_address(args.host, args.port)
        self.selector = selectors.DefaultSelector()
        self.schedule = _Schedule(args.connections)
        self.scratch = bytearray(READ_BUDGET)
        self.body = b"x" * args.body_bytes
        self.interval_ns = max(
            1, round(args.interval * 1000000000)
        )
        self.clients = [
            _Client(index) for index in range(args.connections)
        ]
        self.handshakes_left = args.connections
        self.work_left = args.connections
        self.alive = 0
        self.failed = 0
        self.scheduled = 0
        self.completed = 0
        self.errors: list[str] = []
        self.epoch: int | None = None
        self.deadline: int | None = None
        self.closing = False
        self.finished_ns = 0
        self.scheduled_latency = LatencyHistogram()
        self.wire_latency = LatencyHistogram()
        self.scheduling_delay = LatencyHistogram()

        run_id = secrets.token_hex(6)
        for client in self.clients:
            room = (
                args.room
                if args.rooms == 1
                else f"{args.room}.{client.index % args.rooms}"
            )
            user = f"{args.user_prefix}_{run_id}_{client.index}"

            try:
                peer = ProtocolClient(
                    self.address, user, token, room
                )
                client.peer = peer
                client.handshake_deadline = (
                    time.monotonic_ns()
                    + round(args.connect_timeout * 1000000000)
                )
                self.selector.register(
                    peer.socket, peer.interest, client
                )
                client.fd = peer.socket.fileno()
                client.registered = True
                self.alive += 1
                self._arm(client)
            except Exception as exc:
                self._fail(client, str(exc))

    def _fail(self, client: _Client, message: str) -> None:
        if client.failed:
            return

        client.failed = True
        self.failed += 1
        if len(self.errors) < 20:
            self.errors.append(
                f"connection {client.index}: {message[:512]}"
            )
        if not client.resolved:
            client.resolved = True
            self.handshakes_left -= 1
        if not client.work_done:
            client.work_done = True
            self.work_left -= 1
        self._close(client)

    def _close(self, client: _Client) -> None:
        peer = client.peer
        self.schedule.remove(client.index)

        if client.registered:
            if client.fd in self.selector.get_map():
                self.selector.unregister(client.fd)
            client.registered = False
            self.alive -= 1

        if peer is not None:
            peer.close()

    def _intended(self, client: _Client) -> int:
        assert self.epoch is not None
        stagger = (
            client.index * self.interval_ns // self.args.connections
        )
        return (
            self.epoch
            + stagger
            + (client.next_message - 1) * self.interval_ns
        )

    def _can_enqueue(self, client: _Client) -> bool:
        peer = client.peer
        if peer is None or peer.phase != Phase.ACTIVE:
            return False

        frame_size = (
            HEADER.size
            + len(encode_string(peer.room or ""))
            + 10
            + len(self.body)
        )
        return (
            client.next_message <= self.args.messages
            and len(client.pending) < self.args.max_inflight
            and peer.queued_bytes + frame_size <= MAX_TX_BYTES
        )

    def _arm(self, client: _Client) -> None:
        peer = client.peer
        if peer is None or peer.phase == Phase.CLOSED:
            self.schedule.remove(client.index)
            return

        candidates: list[int] = []
        if not client.resolved:
            candidates.append(client.handshake_deadline)
        if self.deadline is not None:
            candidates.append(self.deadline)
        if (
            peer.phase == Phase.ACTIVE
            and peer.pending_ping is None
        ):
            candidates.append(peer.next_ping_ns)
        if (
            self.epoch is not None
            and not self.closing
            and self._can_enqueue(client)
        ):
            candidates.append(self._intended(client))

        if candidates:
            self.schedule.set(client.index, min(candidates))
        else:
            self.schedule.remove(client.index)

        self.selector.modify(
            peer.socket, peer.interest, client
        )

    def _start_epoch(self) -> None:
        if self.epoch is not None or self.handshakes_left:
            return

        self.epoch = time.monotonic_ns() + 50000000
        self.deadline = (
            self.epoch
            + self.args.messages * self.interval_ns
            + round(self.args.drain_timeout * 1000000000)
        )
        for client in self.clients:
            self._arm(client)

    def _pump(self, client: _Client, now: int) -> None:
        peer = client.peer
        if peer is None or peer.phase == Phase.CLOSED:
            return

        if not client.resolved and now >= client.handshake_deadline:
            self._fail(client, "connect/handshake timeout")
            return

        if self.deadline is not None and now >= self.deadline:
            self._fail(
                client, "benchmark or closing deadline expired"
            )
            return

        peer.heartbeat(now)

        # Backpressure bounds materialization without moving intended deadlines.
        while (
            self.epoch is not None
            and not self.closing
            and self._can_enqueue(client)
        ):
            intended = self._intended(client)
            if intended > now:
                break

            message_id = client.next_message
            request_id = 1000 + message_id
            peer.queue_frame(
                4,
                request_id,
                encode_message(
                    peer.room or "", message_id, self.body
                ),
            )
            client.pending[request_id] = _Pending(intended)
            client.next_message += 1
            self.scheduled += 1
            self.scheduling_delay.observe(
                time.monotonic_ns() - intended
            )

        self._arm(client)

    def _read(self, client: _Client) -> None:
        peer = client.peer
        assert peer is not None

        for frame in peer.read_frames(self.scratch):
            if peer.handle_control(frame):
                continue

            if frame.kind != 7:
                raise WireError(
                    f"unexpected server frame {frame.kind}"
                )

            kind, durable, seq = decode_ack(frame)
            if kind != 4 or durable != 1 or not seq:
                raise WireError(
                    "MSG acknowledgment is not durable"
                )

            pending = client.pending.pop(frame.request_id, None)
            if pending is None or not pending.sent_ns:
                raise WireError(
                    "ACK for an unknown or incompletely sent message"
                )

            now = time.monotonic_ns()
            self.scheduled_latency.observe(
                now - pending.intended_ns
            )
            self.wire_latency.observe(now - pending.sent_ns)
            self.completed += 1
            client.acknowledged += 1
            self.finished_ns = now

            if (
                client.acknowledged == self.args.messages
                and not client.work_done
            ):
                client.work_done = True
                self.work_left -= 1

        if peer.phase == Phase.ACTIVE and not client.resolved:
            client.resolved = True
            self.handshakes_left -= 1

        if peer.eof:
            if peer.phase != Phase.CLOSING or client.pending:
                raise WireError("unexpected EOF")
            self._close(client)

    def _begin_close(self) -> None:
        if self.closing or self.work_left:
            return

        self.closing = True
        self.deadline = (
            time.monotonic_ns()
            + round(self.args.drain_timeout * 1000000000)
        )
        for client in self.clients:
            peer = client.peer
            if peer is not None and peer.phase != Phase.CLOSED:
                peer.begin_close()
                self._arm(client)

    def run(self) -> tuple[int, dict[str, Any]]:
        try:
            interrupted = False
            try:
                while self.alive:
                    self._start_epoch()
                    self._begin_close()
                    now = time.monotonic_ns()

                    while True:
                        index = self.schedule.pop_due(now)
                        if index is None:
                            break

                        client = self.clients[index]
                        try:
                            self._pump(client, now)
                        except Exception as exc:
                            self._fail(client, str(exc))
                        now = time.monotonic_ns()

                    if not self.alive:
                        break

                    next_deadline = self.schedule.first()
                    timeout = (
                        None
                        if next_deadline is None
                        else max(
                            0.0,
                            (next_deadline - now) / 1000000000,
                        )
                    )

                    for key, mask in self.selector.select(timeout):
                        client = key.data
                        peer = client.peer
                        if peer is None or peer.phase == Phase.CLOSED:
                            continue

                        try:
                            if mask & selectors.EVENT_WRITE:
                                for request_id, sent_ns in peer.flush():
                                    client.pending[
                                        request_id
                                    ].sent_ns = sent_ns

                            if mask & selectors.EVENT_READ:
                                self._read(client)

                            self._arm(client)
                        except Exception as exc:
                            self._fail(client, str(exc))

            except KeyboardInterrupt:
                interrupted = True
                for client in self.clients:
                    if (
                        client.peer is not None
                        and client.peer.phase != Phase.CLOSED
                    ):
                        self._fail(client, "interrupted")

            expected = self.args.connections * self.args.messages
            duration_ns = max(
                0,
                self.finished_ns
                - (self.epoch or self.finished_ns),
            )

            report = {
                "target": {
                    "host": self.address[0],
                    "port": self.address[1],
                },
                "interrupted": interrupted,
                "connections": self.args.connections,
                "body_bytes": self.args.body_bytes,
                "rooms": self.args.rooms,
                "interval_ns_per_connection": self.interval_ns,
                "max_inflight_per_connection": self.args.max_inflight,
                "measured_seconds": duration_ns / 1000000000,
                "failed_connections": self.failed,
                "offered_messages": expected,
                "enqueued_messages": self.scheduled,
                "durable_acks": self.completed,
                "missing_acks": expected - self.completed,
                "not_enqueued": expected - self.scheduled,
                "offered_messages_per_second": (
                    self.args.connections
                    * 1000000000
                    / self.interval_ns
                ),
                "achieved_acks_per_second": (
                    self.completed * 1000000000 / duration_ns
                    if duration_ns else 0
                ),
                "scheduled_to_ack": self.scheduled_latency.summary(),
                "last_send_to_ack": self.wire_latency.summary(),
                "client_scheduling_delay": self.scheduling_delay.summary(),
                "latency_reference": (
                    "fixed intended deadlines; unfinished offered "
                    "slots are counted separately"
                ),
                "errors": self.errors,
            }

            status = (
                130
                if interrupted
                else (
                    0
                    if self.completed == expected and not self.failed
                    else 1
                )
            )
            return status, report
        finally:
            for client in self.clients:
                self._close(client)
            self.selector.close()


def authentication_token(argument: str | None) -> str:
    token = (
        argument
        if argument is not None
        else os.environ.get("VICTORY_TOKEN", "")
    )
    if not 1 <= len(token.encode("utf-8")) <= 256 or "\x00" in token:
        raise ValueError(
            "provide --token or a nonempty VICTORY_TOKEN "
            "of at most 256 UTF-8 bytes"
        )
    return token


def health_check(
    address: tuple[str, int], token: str, timeout: float
) -> None:
    peer = handshake(
        address,
        "health_" + secrets.token_hex(6),
        token,
        None,
        timeout=timeout,
    )
    peer.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Fixed-clock Victory protocol load generator"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--token")
    parser.add_argument("--connections", type=int, default=100)
    parser.add_argument("--messages", type=int, default=100)
    parser.add_argument(
        "--interval",
        type=float,
        default=0.1,
        help="intended seconds between messages per connection",
    )
    parser.add_argument("--body-bytes", type=int, default=256)
    parser.add_argument("--max-inflight", type=int, default=32)
    parser.add_argument("--room", default="bench")
    parser.add_argument("--rooms", type=int, default=1)
    parser.add_argument("--user-prefix", default="load")
    parser.add_argument(
        "--connect-timeout", type=float, default=10.0
    )
    parser.add_argument(
        "--drain-timeout", type=float, default=30.0
    )
    parser.add_argument("--healthcheck", action="store_true")
    args = parser.parse_args()

    try:
        token = authentication_token(args.token)

        if (
            not 1 <= args.port <= 65535
            or not 1 <= args.connections <= 100000
        ):
            raise ValueError("invalid port or connection count")

        if (
            not 1 <= args.messages <= 0xFFFFFFFF - 1000
            or not 0 <= args.body_bytes <= MAX_BODY
        ):
            raise ValueError("invalid message count or body size")

        if (
            not 1 <= args.max_inflight <= 4096
            or not 1 <= args.rooms <= args.connections
        ):
            raise ValueError("invalid inflight or room limit")

        for value in (
            args.interval,
            args.connect_timeout,
            args.drain_timeout,
        ):
            if not math.isfinite(value) or not 0 < value <= 3600:
                raise ValueError(
                    "time intervals must be finite and "
                    "within (0, 3600] seconds"
                )

        longest_room = (
            args.room
            if args.rooms == 1
            else f"{args.room}.{args.rooms - 1}"
        )
        if (
            not ROOM_PATTERN.fullmatch(args.room)
            or not ROOM_PATTERN.fullmatch(longest_room)
        ):
            raise ValueError("invalid room name")

        longest_user = (
            f"{args.user_prefix}_{'0' * 12}_{args.connections - 1}"
        )
        if not USER_PATTERN.fullmatch(longest_user):
            raise ValueError(
                "user prefix is invalid or too long"
            )

        if args.healthcheck:
            health_check(
                resolve_address(args.host, args.port),
                token,
                args.connect_timeout,
            )
            return 0

        status, report = LoadGenerator(args, token).run()
        print(json.dumps(report, sort_keys=True))
        return status

    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(
            json.dumps({
                "error": f"{type(exc).__name__}: {exc}"
            }),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())