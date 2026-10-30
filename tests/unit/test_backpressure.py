from __future__ import annotations

import errno
import gc
import itertools
import logging
import socket
import struct
import sys
import tracemalloc
from collections import deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import cast

import pytest

from victory.net.backends import READ, WRITE, Backend
from victory.net.connection import (
    HARD_LIMIT,
    LOW_WATERMARK,
    SOFT_LIMIT,
    WRITE_BUDGET,
    Connection,
    ConnectionFailure,
    ConnectionState,
    FailureKind,
)
from victory.protocol.decoder import FrameDecoder
from victory.protocol.frame import Frame, FrameType

_HEADER = struct.Struct("!HBBBBII")
_PING = struct.Struct("!Q")
_ERROR_PREFIX = struct.Struct("!HBH")

_LOGGER = logging.getLogger("victory.tests.backpressure")
_FD_SEQUENCE = itertools.count(1000)
_PACKET_SIZE = 64 * 1024
_BOOKKEEPING_ALLOWANCE = 64 * 1024


@dataclass(frozen=True, slots=True)
class _Registration:
    mask: int
    data: object


class _MockBackend:
    def __init__(self) -> None:
        self.registry: dict[int, _Registration] = {}
        self.changes: deque[tuple[int, int]] = deque(maxlen=128)
        self.unregister_count = 0

    def register(
        self,
        fd: int,
        mask: int,
        data: object = None,
    ) -> None:
        assert fd not in self.registry
        self.registry[fd] = _Registration(mask, data)

    def modify(
        self,
        fd: int,
        mask: int,
        data: object = None,
    ) -> None:
        assert fd in self.registry
        self.registry[fd] = _Registration(mask, data)
        self.changes.append((fd, mask))

    def unregister(self, fd: int) -> None:
        if fd in self.registry:
            del self.registry[fd]
            self.unregister_count += 1


class _MockSocket:
    def __init__(
        self,
        *,
        blocked: bool = False,
        max_send: int = WRITE_BUDGET,
    ) -> None:
        self.fd = next(_FD_SEQUENCE)
        self.blocking = True
        self.closed = False
        self.blocked = blocked
        self.max_send = max_send
        self.allowance = WRITE_BUDGET

        self.incoming: deque[memoryview] = deque()
        self.received = bytearray()
        self.send_calls_this_turn = 0
        self.sent_this_turn = 0

    def fileno(self) -> int:
        return -1 if self.closed else self.fd

    def setblocking(self, blocking: bool) -> None:
        assert not self.closed
        self.blocking = blocking

    def feed(self, data: bytes) -> None:
        assert not self.closed
        self.incoming.append(memoryview(data))

    def begin_turn(self, allowance: int = WRITE_BUDGET) -> None:
        assert allowance >= 0
        self.allowance = allowance
        self.send_calls_this_turn = 0
        self.sent_this_turn = 0

    def recv_into(
        self,
        buf: bytearray,
        size: int = 0,
    ) -> int:
        assert not self.closed
        assert not self.blocking

        if not self.incoming:
            raise BlockingIOError(
                errno.EAGAIN,
                "no inbound data",
            )

        head = self.incoming[0]
        count = min(
            len(head),
            size or len(buf),
            len(buf),
        )

        with memoryview(buf) as destination:
            with head[:count] as source:
                destination[:count] = source

        if count == len(head):
            self.incoming.popleft().release()
        else:
            self.incoming[0] = head[count:]
            head.release()

        return count

    def send(self, data: memoryview) -> int:
        assert not self.closed
        assert not self.blocking

        if self.blocked or self.allowance == 0:
            raise BlockingIOError(
                errno.EWOULDBLOCK,
                "peer is not reading",
            )

        count = min(
            len(data),
            self.max_send,
            self.allowance,
        )

        with memoryview(data) as view:
            with view[:count] as sent:
                self.received.extend(sent)

        self.allowance -= count
        self.send_calls_this_turn += 1
        self.sent_this_turn += count
        return count

    def take_output(self) -> bytes:
        data = bytes(self.received)
        self.received = bytearray()
        return data

    def close(self) -> None:
        if self.closed:
            return

        self.closed = True
        while self.incoming:
            self.incoming.popleft().release()


class _MockReactor:
    """One fair read phase and write phase per logical loop turn."""

    def __init__(self) -> None:
        self.backend = _MockBackend()
        self.connections: dict[int, Connection] = {}
        self.failures: deque[ConnectionFailure] = deque(maxlen=64)
        self.scratch = bytearray(64 * 1024)

    def add_client(self, *, blocked: bool = False) -> Connection:
        sock = _MockSocket(
            blocked=blocked,
            max_send=WRITE_BUDGET if blocked else 7,
        )
        connection = Connection(
            cast(socket.socket, sock),
            cast(Backend, self.backend),
        )

        self.connections[connection.fd] = connection
        assert not sock.blocking
        return connection

    def _retire_closed(self) -> None:
        for fd, connection in list(self.connections.items()):
            if connection.state != ConnectionState.CLOSED:
                continue

            assert fd not in self.backend.registry
            failure = connection.failure

            # Connection exposes failures; the loop owns their logging.
            if failure is not None:
                self.failures.append(failure)
                _LOGGER.warning(
                    "fd=%d kind=%s code=%s fatal=True: %s",
                    fd,
                    failure.kind.name,
                    failure.protocol_code,
                    failure.message,
                )

            del self.connections[fd]

    def queue(self, fd: int, data: bytes) -> bool:
        accepted = self.connections[fd].queue_bytes(data)
        self._retire_closed()
        return accepted

    def step(self) -> None:
        for connection in list(self.connections.values()):
            sock = cast(_MockSocket, connection.sock)
            sock.begin_turn()

            registration = self.backend.registry[connection.fd]
            if registration.mask & READ and sock.incoming:
                frames = connection.handle_events(
                    READ,
                    self.scratch,
                )
                for frame in frames:
                    assert connection.queue_frame(frame)

        for connection in list(self.connections.values()):
            sock = cast(_MockSocket, connection.sock)
            registration = self.backend.registry.get(connection.fd)

            if (
                registration is not None
                and registration.mask & WRITE
                and not sock.blocked
            ):
                connection.handle_events(
                    WRITE,
                    self.scratch,
                )

        self._retire_closed()

    def close(self) -> None:
        for connection in list(self.connections.values()):
            connection.close()

        self._retire_closed()
        assert not self.backend.registry


@pytest.fixture
def reactor() -> Iterator[_MockReactor]:
    loop = _MockReactor()
    try:
        yield loop
    finally:
        loop.close()


def _large_packet(request_id: int) -> bytes:
    payload_size = _PACKET_SIZE - _HEADER.size
    payload = b"data=" + b"x" * (payload_size - 6) + b"\n"

    return _HEADER.pack(
        0xCE57,
        1,
        int(FrameType.STATS_OK),
        0,
        0,
        request_id,
        len(payload),
    ) + payload


def _ping_packet(request_id: int, nonce: int) -> bytes:
    payload = _PING.pack(nonce)

    return _HEADER.pack(
        0xCE57,
        1,
        int(FrameType.PING),
        0,
        0,
        request_id,
        len(payload),
    ) + payload


def _buffer_footprint(
    connections: Iterable[Connection],
) -> int:
    """Count buffer containers and unique shared backing allocations."""
    seen: set[int] = set()
    total = 0

    def count(value: object) -> None:
        nonlocal total

        if id(value) not in seen:
            seen.add(id(value))
            total += sys.getsizeof(value)

    for connection in connections:
        count(connection)
        count(connection.__dict__)
        count(connection._inbound)
        count(connection._outbound)
        count(connection._errors)

        for view in connection._outbound:
            count(view)
            count(view.obj)

        decoder = connection.decoder
        if decoder is not None:
            count(decoder)
            count(decoder._header)
            count(decoder._payload)
            count(decoder._errors)

    return total


def _assert_allocation_bound(reactor: _MockReactor) -> int:
    connections = list(reactor.connections.values())
    logical_bytes = sum(
        connection.queued_bytes
        for connection in connections
    )

    assert all(
        0 <= connection.queued_bytes <= HARD_LIMIT
        for connection in connections
    )
    assert logical_bytes <= len(connections) * HARD_LIMIT

    footprint = _buffer_footprint(connections)

    # Watermarks count logical bytes; Python containers add bookkeeping.
    assert footprint <= (
        logical_bytes
        + len(connections) * _BOOKKEEPING_ALLOWANCE
    )

    return footprint


def test_soft_watermark_toggle_verification(
    reactor: _MockReactor,
) -> None:
    connection = reactor.add_client()
    sock = cast(_MockSocket, connection.sock)
    sock.max_send = WRITE_BUDGET

    assert (
        LOW_WATERMARK,
        SOFT_LIMIT,
        HARD_LIMIT,
    ) == (
        65_536,
        262_144,
        1_048_576,
    )

    assert connection.queue_bytes(b"a" * (SOFT_LIMIT - 1))
    assert connection.queued_bytes == SOFT_LIMIT - 1
    assert not connection.read_paused
    assert connection.mask == (READ | WRITE)
    assert reactor.backend.registry[connection.fd].mask == (
        READ | WRITE
    )

    assert connection.queue_bytes(b"b")
    assert connection.queued_bytes == SOFT_LIMIT
    assert connection.read_paused
    assert connection.state == ConnectionState.OPEN
    assert connection.mask == WRITE
    assert reactor.backend.registry[connection.fd].mask == WRITE
    assert reactor.backend.registry[connection.fd].data is connection

    assert connection.queue_bytes(b"c" * 17)

    while connection.queued_bytes > LOW_WATERMARK:
        allowance = min(
            WRITE_BUDGET,
            connection.queued_bytes - LOW_WATERMARK,
        )
        sock.begin_turn(allowance)

        assert connection.write_ready() == allowance
        assert connection.read_paused
        assert reactor.backend.registry[connection.fd].mask == WRITE

    assert connection.queued_bytes == LOW_WATERMARK
    assert connection.read_paused
    assert connection.mask == WRITE

    sock.begin_turn(1)
    assert connection.write_ready() == 1
    assert connection.queued_bytes == LOW_WATERMARK - 1
    assert not connection.read_paused
    assert connection.mask == (READ | WRITE)
    assert reactor.backend.registry[connection.fd].mask == (
        READ | WRITE
    )

    sock.begin_turn()
    assert connection.write_ready() == LOW_WATERMARK - 1
    assert connection.queued_bytes == 0
    assert connection.mask == READ
    assert reactor.backend.registry[connection.fd].mask == READ

    assert sock.take_output() == (
        b"a" * (SOFT_LIMIT - 1)
        + b"b"
        + b"c" * 17
    )
    assert connection.failure is None


def test_slow_consumer_hard_eviction_policy(
    reactor: _MockReactor,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger=_LOGGER.name)

    healthy = [reactor.add_client() for _ in range(10)]
    decoders = {
        connection.fd: FrameDecoder()
        for connection in healthy
    }
    slow = reactor.add_client(blocked=True)
    slow_sock = cast(_MockSocket, slow.sock)

    eviction_turn: int | None = None
    peak_footprint = 0

    for turn in range(1, 65):
        expected: dict[int, bytes] = {}

        for index, connection in enumerate(healthy):
            packet = _ping_packet(
                turn,
                (turn << 16) | index,
            )
            expected[connection.fd] = packet
            cast(_MockSocket, connection.sock).feed(packet)

        if slow.fd in reactor.connections:
            admitted = reactor.queue(
                slow.fd,
                _large_packet(turn),
            )

            if turn <= HARD_LIMIT // _PACKET_SIZE:
                assert admitted
                assert slow.queued_bytes == turn * _PACKET_SIZE

                if slow.queued_bytes >= SOFT_LIMIT:
                    assert slow.read_paused
                    assert reactor.backend.registry[slow.fd].mask == WRITE
            else:
                assert not admitted
                eviction_turn = turn

                assert slow.state == ConnectionState.CLOSED
                assert slow.fd not in reactor.connections
                assert slow.fd not in reactor.backend.registry
                assert slow_sock.closed
                assert slow.fileno() == -1
                assert slow.queued_bytes == 0
                assert not slow._outbound

        peak_footprint = max(
            peak_footprint,
            _assert_allocation_bound(reactor),
        )
        reactor.step()

        # Turn latency checks isolation without machine-dependent timing.
        for index, connection in enumerate(healthy):
            sock = cast(_MockSocket, connection.sock)
            echoed = sock.take_output()

            assert echoed == expected[connection.fd]
            assert decoders[connection.fd].feed(echoed) == [
                Frame(
                    FrameType.PING,
                    turn,
                    _PING.pack((turn << 16) | index),
                )
            ]
            assert connection.state == ConnectionState.OPEN
            assert connection.failure is None
            assert connection.queued_bytes == 0
            assert reactor.backend.registry[connection.fd].mask == READ
            assert sock.sent_this_turn == len(expected[connection.fd])
            assert sock.send_calls_this_turn == 4

    assert eviction_turn == HARD_LIMIT // _PACKET_SIZE + 1
    assert len(reactor.connections) == 10
    assert len(reactor.backend.registry) == 10
    assert reactor.backend.unregister_count == 1

    assert slow.failure is not None
    assert slow.failure.kind == FailureKind.SLOW_CONSUMER
    assert slow.failure.protocol_code == 14
    assert list(reactor.failures) == [slow.failure]
    assert slow_sock.take_output() == b""

    assert peak_footprint < (
        11 * (HARD_LIMIT + _BOOKKEEPING_ALLOWANCE)
    )
    assert any(
        "SLOW_CONSUMER" in record.getMessage()
        and "code=14" in record.getMessage()
        and "fatal=True" in record.getMessage()
        for record in caplog.records
    )


def test_hard_limit_emits_fatal_error_when_writable(
    reactor: _MockReactor,
) -> None:
    connection = reactor.add_client()
    sock = cast(_MockSocket, connection.sock)

    assert not reactor.queue(
        connection.fd,
        b"x" * (HARD_LIMIT + 1),
    )
    assert connection.state == ConnectionState.CLOSED
    assert connection.fd not in reactor.backend.registry
    assert connection.fd not in reactor.connections

    frames = FrameDecoder().feed(sock.take_output())
    assert len(frames) == 1

    frame = frames[0]
    assert frame.type == FrameType.ERROR
    assert frame.request_id == 0

    message = b"SLOW_CONSUMER"
    assert frame.payload == (
        _ERROR_PREFIX.pack(14, 1, len(message))
        + message
    )
    assert connection.failure is not None
    assert connection.failure.protocol_code == 14


def test_memory_isolation_i5(
    reactor: _MockReactor,
) -> None:
    healthy = [reactor.add_client() for _ in range(10)]

    tracing_owned = not tracemalloc.is_tracing()
    if tracing_owned:
        tracemalloc.start()

    gc.collect()
    baseline, _baseline_peak = tracemalloc.get_traced_memory()
    peak_live = baseline

    settled_slack = 512 * 1024
    live_budget = (
        HARD_LIMIT
        + 11 * _BOOKKEEPING_ALLOWANCE
        + 2 * _PACKET_SIZE
    )

    try:
        for cycle in range(24):
            slow = reactor.add_client(blocked=True)

            for chunk in range(HARD_LIMIT // _PACKET_SIZE):
                assert reactor.queue(
                    slow.fd,
                    _large_packet(cycle * 32 + chunk),
                )
                _assert_allocation_bound(reactor)

                current, _peak = tracemalloc.get_traced_memory()
                peak_live = max(peak_live, current)

            assert slow.queued_bytes == HARD_LIMIT
            assert slow.state == ConnectionState.OPEN

            assert not reactor.queue(slow.fd, b"overflow")
            assert slow.state == ConnectionState.CLOSED
            assert slow.fd not in reactor.connections
            assert slow.queued_bytes == 0
            assert slow.buffered_input_bytes == 0
            assert not slow._outbound
            assert slow.decoder is None

            for _ in range(128):
                assert not slow.queue_bytes(
                    b"discarded after eviction"
                )

            for index, connection in enumerate(healthy):
                cast(_MockSocket, connection.sock).feed(
                    _ping_packet(cycle, index)
                )

            reactor.step()

            for index, connection in enumerate(healthy):
                assert cast(
                    _MockSocket,
                    connection.sock,
                ).take_output() == _ping_packet(cycle, index)

                assert connection.state == ConnectionState.OPEN
                assert connection.failure is None

            assert len(reactor.connections) == 10
            assert len(reactor.backend.registry) == 10
            _assert_allocation_bound(reactor)

            gc.collect()
            current, _peak = tracemalloc.get_traced_memory()
            assert current - baseline < settled_slack

        assert peak_live - baseline < live_budget

        if tracing_owned:
            _current, peak = tracemalloc.get_traced_memory()
            assert peak - baseline < live_budget

        assert reactor.backend.unregister_count == 24
        assert len(reactor.failures) == 24
        assert all(
            failure.kind == FailureKind.SLOW_CONSUMER
            and failure.protocol_code == 14
            for failure in reactor.failures
        )
    finally:
        if tracing_owned:
            tracemalloc.stop()