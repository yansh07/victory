from __future__ import annotations

import errno
import math
import socket
from collections import deque
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import cast

import pytest

import victory.cluster.redis_bus as redis_bus_module
from victory.cluster.bus import (
    BUS_VERSION,
    BusMessage,
    InProcessBus,
    InProcessHub,
    channel_for,
)
from victory.cluster.redis_bus import (
    LinkRole,
    LinkState,
    RedisClusterBus,
)
from victory.cluster.resp import (
    DecoderState,
    RespDecoder,
    RespValue,
)
from victory.core.router import (
    Action,
    AppendWalAction,
    EnqueueClientBufferAction,
    Router,
)
from victory.core.session import Session, SessionState
from victory.net.backends import READ, WRITE, Backend, Event
from victory.net.timers import TimerHeap
from victory.protocol.codec import (
    Ack,
    Deliver,
    Hello,
    Join,
    Msg,
    decode_frame,
    encode_payload,
    make_frame,
)
from victory.protocol.frame import Frame, FrameType

_ROOM = "general"
_TOKEN = "cluster-test-token"
_REDIS_PASSWORD = "redis-test-password"
_CRLF = b"\r\n"


def _bulk(value: bytes) -> bytes:
    return (
        b"$"
        + str(len(value)).encode("ascii")
        + _CRLF
        + value
        + _CRLF
    )


def _array(values: Sequence[bytes | int]) -> bytes:
    parts = [
        b"*"
        + str(len(values)).encode("ascii")
        + _CRLF
    ]
    for value in values:
        if isinstance(value, bytes):
            parts.append(_bulk(value))
        else:
            parts.append(
                b":"
                + str(value).encode("ascii")
                + _CRLF
            )
    return b"".join(parts)


def _delivery_payload(
    origin_node: int,
    *,
    sequence: int = 1,
) -> bytes:
    return encode_payload(
        Deliver(
            _ROOM,
            origin_node,
            sequence,
            "alice",
            999,
            b"binary\x00\r\n\xffmessage",
        )
    )


@dataclass(slots=True)
class _Node:
    router: Router
    bus: InProcessBus
    inboxes: dict[int, list[Frame]] = field(
        default_factory=dict
    )

    def enqueue(self, actions: Sequence[Action]) -> None:
        for action in actions:
            assert isinstance(
                action,
                EnqueueClientBufferAction,
            )
            assert action.packet == action.frame.to_bytes()
            self.inboxes.setdefault(
                action.session_id,
                [],
            ).append(action.frame)

    def connect_user(self, user: str) -> Session:
        session = self.router.open_session()

        self.enqueue(
            self.router.route(
                session.session_id,
                make_frame(
                    Hello(0, user, _TOKEN),
                    request_id=1,
                ),
            )
        )
        assert session.state == SessionState.ACTIVE

        self.enqueue(
            self.router.route(
                session.session_id,
                make_frame(
                    Join(_ROOM),
                    request_id=2,
                ),
            )
        )
        assert self.router.rooms.is_member(
            session.session_id,
            _ROOM,
        )
        assert self.bus.subscribe(_ROOM)

        self.inboxes[session.session_id].clear()
        return session

    def receive_bus(self) -> list[BusMessage]:
        messages = self.bus.poll()

        for message in messages:
            frame = message.to_frame()
            for session_id in sorted(
                self.router.rooms.members(message.room)
            ):
                session = self.router.get_session(session_id)
                assert session is not None

                if (
                    not session.closing
                    and session.state == SessionState.ACTIVE
                ):
                    self.inboxes.setdefault(
                        session_id,
                        [],
                    ).append(frame)

        return messages


@dataclass(slots=True)
class _ManualClock:
    now: float = 0.0

    def __call__(self) -> float:
        return self.now

    def advance_to(self, value: float) -> None:
        assert math.isfinite(value)
        assert value >= self.now
        self.now = value


@dataclass(frozen=True, slots=True)
class _Registration:
    mask: int
    data: object


def _extract_command(
    data: bytearray,
) -> tuple[list[bytes], int] | None:
    """Independent test-server parser for flat bulk-string arguments."""
    if not data:
        return None

    assert data[0] == ord("*")
    end = data.find(_CRLF, 1)
    if end < 0:
        return None

    count = int(data[1:end])
    assert count > 0

    position = end + 2
    arguments: list[bytes] = []

    for _ in range(count):
        if position >= len(data):
            return None

        assert data[position] == ord("$")
        end = data.find(_CRLF, position + 1)
        if end < 0:
            return None

        length = int(data[position + 1:end])
        assert length >= 0

        start = end + 2
        finish = start + length
        if finish + 2 > len(data):
            return None

        assert data[finish:finish + 2] == _CRLF

        with memoryview(data) as view:
            arguments.append(bytes(view[start:finish]))

        position = finish + 2

    return arguments, position


class _MockRedisSocket:
    def __init__(
        self,
        server: _MockRedisServer,
        fd: int,
    ) -> None:
        self.server = server
        self.fd = fd
        self.closed = False
        self.blocking = True
        self.connected = False
        self.authenticated = False

        self.options: dict[tuple[int, int], int] = {}
        self.incoming: deque[memoryview] = deque()
        self.command_buffer = bytearray()
        self.commands: list[list[bytes]] = []
        self.subscriptions: set[bytes] = set()

        self.receive_failure: OSError | None = None
        self.send_failure: OSError | None = None
        self.receive_calls = 0

    def fileno(self) -> int:
        return -1 if self.closed else self.fd

    def setblocking(self, blocking: bool) -> None:
        assert not self.closed
        self.blocking = blocking

    def setsockopt(
        self,
        level: int,
        option: int,
        value: int,
    ) -> None:
        assert not self.closed
        assert not self.blocking
        self.options[(level, option)] = value

    def connect_ex(self, address: tuple[str, int]) -> int:
        assert not self.closed
        assert not self.blocking
        assert address == ("127.0.0.1", 6379)

        if self.server.connect_results:
            return self.server.connect_results.popleft()

        return errno.EINPROGRESS

    def getsockopt(self, level: int, option: int) -> int:
        assert not self.closed
        assert not self.blocking
        assert (level, option) == (
            socket.SOL_SOCKET,
            socket.SO_ERROR,
        )
        self.connected = True
        return 0

    def push_reply(self, packet: bytes) -> None:
        assert not self.closed
        self.incoming.append(memoryview(packet))

    def recv_into(
        self,
        target: bytearray,
        size: int = 0,
    ) -> int:
        assert not self.closed
        assert not self.blocking
        self.receive_calls += 1

        if self.receive_failure is not None:
            failure = self.receive_failure
            self.receive_failure = None
            raise failure

        if not self.incoming:
            raise BlockingIOError(
                errno.EAGAIN,
                "no Redis reply available",
            )

        head = self.incoming[0]
        count = min(
            1,
            len(head),
            size or len(target),
            len(target),
        )

        with memoryview(target) as destination:
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
        assert self.connected

        if self.send_failure is not None:
            failure = self.send_failure
            self.send_failure = None
            raise failure

        count = min(11, len(data))
        with memoryview(data) as view:
            self.command_buffer.extend(view[:count])

        while True:
            parsed = _extract_command(self.command_buffer)
            if parsed is None:
                break

            arguments, consumed = parsed
            self.commands.append(arguments)
            del self.command_buffer[:consumed]
            self.server.execute(self, arguments)

        return count

    def close(self) -> None:
        if self.closed:
            return

        self.closed = True
        while self.incoming:
            self.incoming.popleft().release()

        self.command_buffer = bytearray()
        self.subscriptions.clear()


class _MockRedisServer:
    def __init__(self) -> None:
        self.next_fd = 1000
        self.reuse_next_fd: int | None = None
        self.sockets: dict[int, _MockRedisSocket] = {}
        self.created: list[_MockRedisSocket] = []
        self.connect_results: deque[int] = deque()
        self.publications: list[tuple[bytes, bytes]] = []

    def socket(
        self,
        family: int,
        kind: int,
    ) -> _MockRedisSocket:
        assert family in (
            socket.AF_INET,
            socket.AF_INET6,
        )
        assert kind == socket.SOCK_STREAM

        if self.reuse_next_fd is None:
            fd = self.next_fd
            self.next_fd += 1
        else:
            fd = self.reuse_next_fd
            self.reuse_next_fd = None

        result = _MockRedisSocket(self, fd)
        self.sockets[fd] = result
        self.created.append(result)
        return result

    def execute(
        self,
        client: _MockRedisSocket,
        arguments: list[bytes],
    ) -> None:
        command = arguments[0]

        if command == b"AUTH":
            assert arguments == [
                b"AUTH",
                _REDIS_PASSWORD.encode("utf-8"),
            ]
            client.authenticated = True
            client.push_reply(b"+OK\r\n")
            return

        assert client.authenticated

        if command == b"PING":
            if len(arguments) == 1:
                client.push_reply(b"+PONG\r\n")
            elif client.subscriptions:
                client.push_reply(
                    _array([b"pong", arguments[1]])
                )
            else:
                client.push_reply(_bulk(arguments[1]))

        elif command == b"SUBSCRIBE":
            assert len(arguments) == 2
            client.subscriptions.add(arguments[1])
            client.push_reply(
                _array(
                    [
                        b"subscribe",
                        arguments[1],
                        len(client.subscriptions),
                    ]
                )
            )

        elif command == b"UNSUBSCRIBE":
            assert len(arguments) == 2
            client.subscriptions.discard(arguments[1])
            client.push_reply(
                _array(
                    [
                        b"unsubscribe",
                        arguments[1],
                        len(client.subscriptions),
                    ]
                )
            )

        elif command == b"PUBLISH":
            assert len(arguments) == 3
            channel, payload = arguments[1], arguments[2]
            self.publications.append((channel, payload))

            receivers = [
                peer
                for peer in self.sockets.values()
                if (
                    not peer.closed
                    and channel in peer.subscriptions
                )
            ]

            for peer in receivers:
                peer.push_reply(
                    _array(
                        [
                            b"message",
                            channel,
                            payload,
                        ]
                    )
                )

            client.push_reply(
                b":"
                + str(len(receivers)).encode("ascii")
                + _CRLF
            )

        else:
            raise AssertionError(
                f"unexpected Redis command: {arguments!r}"
            )


class _MockBackend:
    def __init__(self, server: _MockRedisServer) -> None:
        self.server = server
        self.registry: dict[int, _Registration] = {}
        self.closed = False

    def register(
        self,
        fd: int,
        mask: int,
        data: object = None,
    ) -> None:
        assert not self.closed
        assert fd not in self.registry
        self.registry[fd] = _Registration(mask, data)

    def modify(
        self,
        fd: int,
        mask: int,
        data: object = None,
    ) -> None:
        assert not self.closed
        assert fd in self.registry
        self.registry[fd] = _Registration(mask, data)

    def unregister(self, fd: int) -> None:
        self.registry.pop(fd, None)

    def poll(
        self,
        timeout: float | None = None,
    ) -> list[Event]:
        assert not self.closed
        assert timeout == 0.0

        events: list[Event] = []

        for fd, registration in sorted(self.registry.items()):
            client = self.server.sockets[fd]
            assert not client.closed

            mask = 0
            if registration.mask & READ and (
                client.incoming
                or client.receive_failure is not None
            ):
                mask |= READ

            if registration.mask & WRITE:
                mask |= WRITE

            if mask:
                events.append(
                    Event(fd, mask, registration.data)
                )

        return events

    def close(self) -> None:
        self.registry.clear()
        self.closed = True


@dataclass(slots=True)
class _RedisHarness:
    bus: RedisClusterBus
    backend: _MockBackend
    server: _MockRedisServer
    timers: TimerHeap
    clock: _ManualClock
    received: list[BusMessage] = field(default_factory=list)

    def step(self) -> None:
        self.timers.run_due(self.clock.now)

        for event in self.backend.poll(0.0):
            assert self.bus.handle_event(
                event,
                self.clock.now,
            )

        self.received.extend(self.bus.poll())
        assert self.timers.drain_errors() == []

    def run_until(
        self,
        predicate: Callable[[], bool],
    ) -> None:
        for _ in range(1024):
            self.step()
            if predicate():
                return

        raise AssertionError(
            "mock Redis loop did not reach the expected state"
        )


@pytest.fixture
def redis_harness(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_RedisHarness]:
    server = _MockRedisServer()
    backend = _MockBackend(server)
    timers = TimerHeap()
    clock = _ManualClock()

    proxy = SimpleNamespace(
        socket=server.socket,
        AF_INET=socket.AF_INET,
        AF_INET6=socket.AF_INET6,
        SOCK_STREAM=socket.SOCK_STREAM,
        IPPROTO_TCP=socket.IPPROTO_TCP,
        TCP_NODELAY=socket.TCP_NODELAY,
        SOL_SOCKET=socket.SOL_SOCKET,
        SO_ERROR=socket.SO_ERROR,
    )

    # Replace the transport dependency without replacing socket globally.
    monkeypatch.setattr(
        redis_bus_module,
        "socket",
        proxy,
    )

    bus = RedisClusterBus(
        1,
        backend=cast(Backend, backend),
        timers=timers,
        clock=clock,
        password=_REDIS_PASSWORD,
        reconnect_initial=0.1,
        reconnect_max=0.8,
        heartbeat_interval=60.0,
        random_seed=1234,
    )
    harness = _RedisHarness(
        bus,
        backend,
        server,
        timers,
        clock,
    )

    try:
        yield harness
    finally:
        bus.close()

        assert not backend.closed
        assert not backend.registry
        assert len(timers) == 0
        assert timers.drain_errors() == []
        assert all(
            client.closed
            for client in server.created
        )

        backend.close()


def test_resp2_fragmented_streaming_buffer_parsing() -> None:
    envelope = (
        bytes((BUS_VERSION,))
        + _delivery_payload(2)
    )
    expected = [
        b"message",
        channel_for(_ROOM),
        envelope,
    ]
    packet = _array(expected)
    decoder = RespDecoder()
    emitted: list[RespValue] = []

    with memoryview(packet) as view:
        for index in range(len(packet)):
            result = decoder.feed(view[index:index + 1])
            emitted.extend(result)

            assert decoder.state != DecoderState.FAILED
            assert (
                0
                <= decoder._offset
                <= len(decoder._buffer)
            )
            assert (
                0
                <= decoder.buffered_bytes
                <= len(packet)
            )
            assert decoder.pending_depth <= 1

            if index < len(packet) - 1:
                assert result == []
                assert emitted == []
                assert decoder.feed(b"") == []
            else:
                assert result == [expected]

    assert emitted == [expected]
    assert decoder.state == DecoderState.LINE
    assert decoder.buffered_bytes == decoder.pending_depth == 0
    assert decoder.feed(packet) == [expected]


def test_inprocess_bus_isolation_and_local_subscriber_delivery() -> None:
    hub = InProcessHub()
    first = _Node(
        Router(1, tokens=(_TOKEN,)),
        InProcessBus(1, hub),
    )
    second = _Node(
        Router(2, tokens=(_TOKEN,)),
        InProcessBus(2, hub),
    )

    try:
        alice = first.connect_user("alice")
        bob = second.connect_user("bob")
        body = b"hello Bob\x00\xff"

        actions = first.router.route(
            alice.session_id,
            make_frame(
                Msg(_ROOM, 999, body),
                request_id=50,
            ),
        )

        assert len(actions) == 1
        append = actions[0]
        assert isinstance(append, AppendWalAction)
        assert append.record.seq == 1
        assert first.inboxes[alice.session_id] == []
        assert second.receive_bus() == []

        # Publish only after the simulated durability completion.
        completed = first.router.wal_committed(
            append.commit_id
        )
        first.enqueue(completed)

        delivery = Deliver(
            _ROOM,
            1,
            1,
            "alice",
            999,
            body,
        )
        payload = encode_payload(delivery)

        assert first.bus.publish(_ROOM, payload)
        assert first.receive_bus() == []

        messages = second.receive_bus()
        assert len(messages) == 1
        assert messages[0].room == _ROOM
        assert messages[0].origin_node == 1
        assert messages[0].deliver_payload == payload
        assert messages[0].deliver == delivery

        assert len(second.inboxes[bob.session_id]) == 1
        bob_delivery = second.inboxes[bob.session_id][0]
        assert bob_delivery.type == FrameType.DELIVER
        assert bob_delivery.request_id == 0
        assert decode_frame(bob_delivery) == delivery

        assert [
            decode_frame(frame)
            for frame in first.inboxes[alice.session_id]
        ] == [
            Ack(FrameType.MSG, 1, 1),
            delivery,
        ]

        assert first.bus.self_echo_drops == 1
        assert second.bus.self_echo_drops == 0
        assert first.router.rooms.last_sequence(_ROOM) == 1

        # Remote deliveries must not consume this node's local sequence.
        assert second.router.rooms.last_sequence(_ROOM) == 0
        assert second.receive_bus() == []
        assert len(second.inboxes[bob.session_id]) == 1

    finally:
        hub.close()


def test_echo_loop_suppression_i9(
    redis_harness: _RedisHarness,
) -> None:
    harness = redis_harness
    assert harness.bus.subscribe(_ROOM)
    harness.run_until(lambda: harness.bus.ready)

    subscriber = harness.bus._links[LinkRole.SUBSCRIBER]
    client = cast(_MockRedisSocket, subscriber.sock)
    assert client is not None

    before_commands = sum(
        len(peer.commands)
        for peer in harness.server.created
    )

    client.push_reply(
        _array(
            [
                b"message",
                channel_for(_ROOM),
                bytes((BUS_VERSION,))
                + _delivery_payload(harness.bus.node_id),
            ]
        )
    )

    harness.run_until(
        lambda: harness.bus.self_echo_drops == 1
    )

    assert harness.received == []
    assert (
        harness.bus.pending_messages
        == harness.bus.incoming_bytes
        == 0
    )
    assert harness.bus.publisher_connected
    assert harness.bus.subscriber_connected
    assert harness.server.publications == []
    assert sum(
        len(peer.commands)
        for peer in harness.server.created
    ) == before_commands

    # Verify that suppression does not discard a different origin.
    remote_payload = _delivery_payload(2)
    client.push_reply(
        _array(
            [
                b"message",
                channel_for(_ROOM),
                bytes((BUS_VERSION,)) + remote_payload,
            ]
        )
    )

    harness.run_until(
        lambda: len(harness.received) == 1
    )

    assert harness.received[0].origin_node == 2
    assert (
        harness.received[0].deliver_payload
        == remote_payload
    )
    assert harness.bus.self_echo_drops == 1
    assert harness.server.publications == []
    assert harness.bus.drain_errors() == []


@pytest.mark.parametrize(
    "error_number",
    [
        errno.ECONNRESET,
        errno.ETIMEDOUT,
    ],
)
def test_fault_tolerant_reconnect_backoff_and_resubscription(
    redis_harness: _RedisHarness,
    error_number: int,
) -> None:
    harness = redis_harness
    rooms = {"general", "alerts", "engineering"}

    for room in sorted(rooms):
        assert harness.bus.subscribe(room)

    harness.run_until(lambda: harness.bus.ready)

    publisher = harness.bus._links[LinkRole.PUBLISHER]
    subscriber = harness.bus._links[LinkRole.SUBSCRIBER]
    publisher_socket = publisher.sock
    old_socket = cast(_MockRedisSocket, subscriber.sock)
    old_fd = subscriber.fd
    old_registration = subscriber.registration
    old_generation = subscriber.generation

    assert old_socket is not None
    assert old_registration is not None
    assert publisher_socket is not old_socket
    assert len(harness.server.created) == 2
    assert old_socket.subscriptions == {
        channel_for(room)
        for room in rooms
    }

    old_socket.receive_failure = OSError(
        error_number,
        "injected Redis teardown",
    )
    harness.step()

    assert old_socket.closed
    assert subscriber.state == LinkState.DISCONNECTED
    assert subscriber.fd == -1
    assert subscriber.sock is None
    assert old_fd not in harness.backend.registry
    assert harness.bus.publisher_connected
    assert not harness.bus.subscriber_connected
    assert harness.bus.subscriptions == frozenset(rooms)
    assert subscriber.subscribed == set()
    assert subscriber.controls == {}
    assert subscriber.queued_bytes == 0
    assert subscriber.backoff == 0.2

    retry_timer = subscriber.retry_timer
    assert retry_timer is not None
    assert harness.timers.is_pending(retry_timer)

    deadline = harness.timers.deadline(retry_timer)
    assert deadline is not None
    assert 0.05 <= deadline - harness.clock.now <= 0.15

    created_before = len(harness.server.created)
    harness.clock.advance_to(deadline - 0.001)
    harness.step()
    assert len(harness.server.created) == created_before

    harness.server.connect_results.extend(
        [
            errno.ECONNREFUSED,
            errno.ECONNREFUSED,
        ]
    )

    for expected_backoff in (0.4, 0.8):
        retry_timer = subscriber.retry_timer
        assert retry_timer is not None

        deadline = harness.timers.deadline(retry_timer)
        assert deadline is not None
        previous_backoff = subscriber.backoff

        harness.clock.advance_to(deadline)
        harness.step()

        assert not harness.timers.is_pending(retry_timer)
        assert subscriber.state == LinkState.DISCONNECTED
        assert subscriber.backoff == expected_backoff
        assert harness.bus.publisher_connected
        assert publisher.sock is publisher_socket

        next_timer = subscriber.retry_timer
        assert next_timer is not None
        assert next_timer != retry_timer

        next_deadline = harness.timers.deadline(next_timer)
        assert next_deadline is not None
        delay = next_deadline - harness.clock.now

        assert previous_backoff * 0.5 <= delay
        assert delay <= min(
            0.8,
            previous_backoff * 1.5,
        )

    retry_timer = subscriber.retry_timer
    assert retry_timer is not None
    deadline = harness.timers.deadline(retry_timer)
    assert deadline is not None

    # Reuse the descriptor to exercise immutable event-generation tokens.
    harness.server.reuse_next_fd = old_fd
    harness.clock.advance_to(deadline)
    harness.run_until(lambda: harness.bus.ready)

    replacement = cast(_MockRedisSocket, subscriber.sock)
    assert replacement is not old_socket
    assert replacement.fd == old_fd
    assert not replacement.closed
    assert not replacement.blocking
    assert subscriber.generation == old_generation + 3
    assert subscriber.backoff == 0.1
    assert subscriber.retry_timer is None
    assert subscriber.connect_timer is None
    assert not harness.timers.is_pending(retry_timer)
    assert subscriber.subscribed == rooms
    assert not subscriber.controls

    assert replacement.subscriptions == {
        channel_for(room)
        for room in rooms
    }
    assert [
        command[0]
        for command in replacement.commands
    ] == [
        b"AUTH",
        b"PING",
        b"SUBSCRIBE",
        b"SUBSCRIBE",
        b"SUBSCRIBE",
    ]
    assert {
        command[1]
        for command in replacement.commands
        if command[0] == b"SUBSCRIBE"
    } == {
        channel_for(room)
        for room in rooms
    }

    assert len(harness.backend.registry) == 2
    assert all(
        registration.mask == READ
        for registration in harness.backend.registry.values()
    )

    receive_calls = replacement.receive_calls
    assert harness.bus.handle_event(
        Event(old_fd, READ, old_registration),
        harness.clock.now,
    )
    assert replacement.receive_calls == receive_calls
    assert harness.bus.ready

    errors = harness.bus.drain_errors()
    assert [
        failure.errno
        for failure in errors
    ] == [
        error_number,
        errno.ECONNREFUSED,
        errno.ECONNREFUSED,
    ]
    assert all(
        failure.operation == "subscriber"
        for failure in errors
    )


def test_publisher_write_failure_does_not_replay_uncertain_publications(
    redis_harness: _RedisHarness,
) -> None:
    harness = redis_harness
    assert harness.bus.subscribe(_ROOM)
    harness.run_until(lambda: harness.bus.ready)

    publisher = harness.bus._links[LinkRole.PUBLISHER]
    subscriber_socket = harness.bus._links[
        LinkRole.SUBSCRIBER
    ].sock

    old_socket = cast(_MockRedisSocket, publisher.sock)
    old_socket.send_failure = BrokenPipeError(
        errno.EPIPE,
        "injected broken pipe",
    )

    assert harness.bus.publish(
        _ROOM,
        _delivery_payload(1),
    )
    harness.step()

    assert old_socket.closed
    assert publisher.state == LinkState.DISCONNECTED
    assert publisher.queued_bytes == 0
    assert not publisher.pending
    assert harness.bus.subscriber_connected
    assert harness.server.publications == []
    assert harness.bus.publication_drops == 1

    retry_timer = publisher.retry_timer
    assert retry_timer is not None
    deadline = harness.timers.deadline(retry_timer)
    assert deadline is not None

    harness.clock.advance_to(deadline)
    harness.run_until(lambda: harness.bus.ready)

    assert harness.bus._links[
        LinkRole.SUBSCRIBER
    ].sock is subscriber_socket
    assert harness.server.publications == []
    assert not any(
        command[0] == b"PUBLISH"
        for client in harness.server.created
        for command in client.commands
    )
    assert harness.received == []

    errors = harness.bus.drain_errors()
    assert len(errors) == 1
    assert errors[0].errno == errno.EPIPE


def test_redis_publish_uses_publisher_socket_and_binary_envelope(
    redis_harness: _RedisHarness,
) -> None:
    harness = redis_harness
    assert harness.bus.subscribe(_ROOM)
    harness.run_until(lambda: harness.bus.ready)

    publisher = harness.bus._links[LinkRole.PUBLISHER]
    subscriber = harness.bus._links[LinkRole.SUBSCRIBER]
    publisher_socket = cast(_MockRedisSocket, publisher.sock)
    subscriber_socket = cast(_MockRedisSocket, subscriber.sock)

    assert publisher_socket is not subscriber_socket

    payload = _delivery_payload(1)
    envelope = bytes((BUS_VERSION,)) + payload

    assert harness.bus.publish(_ROOM, payload)
    harness.run_until(
        lambda: harness.bus.self_echo_drops == 1
    )

    assert harness.server.publications == [
        (channel_for(_ROOM), envelope)
    ]
    assert publisher_socket.commands[-1] == [
        b"PUBLISH",
        channel_for(_ROOM),
        envelope,
    ]
    assert not any(
        command[0] == b"PUBLISH"
        for command in subscriber_socket.commands
    )
    assert not publisher.pending
    assert publisher.queued_bytes == 0
    assert harness.received == []
    assert harness.bus.publication_drops == 0
    assert harness.bus.ready
    assert harness.bus.drain_errors() == []