"""Dual-connection RESP2 Pub/Sub with bounded queues and reconnects.

With a supplied backend, route its events to handle_event(); poll()
drains deliveries. With a private backend, poll() also services readiness
using a zero timeout. A supplied TimerHeap remains owned by its caller.
Numeric IP addresses avoid blocking DNS inside the loop.
"""

from __future__ import annotations

import errno
import ipaddress
import math
import socket
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import IntEnum
from functools import partial
from random import Random

from ..net.backends import (
    ERROR,
    HANGUP,
    PEER_CLOSED,
    READ,
    WRITE,
    Backend,
    Event,
    create_backend,
)
from ..net.timers import TimerHeap
from ..protocol.frame import MAX_PAYLOAD
from .bus import (
    BUS_VERSION,
    BusMessage,
    BusState,
    ClusterBus,
    channel_for,
    validate_room,
)
from .resp import (
    RespDecoder,
    RespError,
    RespProtocolError,
    RespValue,
    encode_command,
)

_IO_BUDGET = 64 * 1024
_OPERATION_BUDGET = 64

_WOULD_BLOCK = frozenset(
    (errno.EAGAIN, errno.EWOULDBLOCK)
)
_CONNECTING = frozenset(
    (
        errno.EINPROGRESS,
        errno.EALREADY,
        errno.EINTR,
        errno.EAGAIN,
        errno.EWOULDBLOCK,
    )
)


class LinkRole(IntEnum):
    PUBLISHER = 1
    SUBSCRIBER = 2


class LinkState(IntEnum):
    DISCONNECTED = 1
    CONNECTING = 2
    INITIALIZING = 3
    READY = 4
    CLOSED = 5


class CommandKind(IntEnum):
    AUTH = 1
    PING = 2
    PUBLISH = 3
    SUBSCRIBE = 4
    UNSUBSCRIBE = 5


@dataclass(frozen=True, slots=True)
class _Command:
    kind: CommandKind
    room: str | None = None
    token: bytes | None = None


@dataclass(frozen=True, slots=True)
class _Registration:
    owner: RedisClusterBus
    role: LinkRole
    generation: int


def _new_decoder() -> RespDecoder:
    return RespDecoder(
        max_bulk=MAX_PAYLOAD + 1,
        max_array=16,
        max_depth=8,
        max_line=4096,
        max_message=2 * (MAX_PAYLOAD + 1) + 8192,
        max_values=64,
    )


@dataclass(slots=True)
class _Link:
    role: LinkRole
    state: LinkState = LinkState.DISCONNECTED
    sock: socket.socket | None = None
    fd: int = -1
    generation: int = 0
    registered: bool = False
    mask: int = 0
    registration: _Registration | None = None
    decoder: RespDecoder = field(default_factory=_new_decoder)
    outbound: deque[memoryview] = field(default_factory=deque)
    queued_bytes: int = 0
    pending: deque[_Command] = field(default_factory=deque)
    subscribed: set[str] = field(default_factory=set)
    controls: dict[str, CommandKind] = field(default_factory=dict)
    retry_timer: int | None = None
    connect_timer: int | None = None
    heartbeat_timer: int | None = None
    pong_timer: int | None = None
    pong_token: bytes | None = None
    ping_sequence: int = 0
    backoff: float = 0.1


class RedisClusterBus(ClusterBus):
    def __init__(
        self,
        node_id: int,
        host: str = "127.0.0.1",
        port: int = 6379,
        *,
        backend: Backend | None = None,
        timers: TimerHeap | None = None,
        clock: Callable[[], float] = time.monotonic,
        password: str | None = None,
        username: str | None = None,
        reconnect_initial: float = 0.1,
        reconnect_max: float = 30.0,
        connect_timeout: float = 5.0,
        heartbeat_interval: float = 10.0,
        heartbeat_timeout: float = 5.0,
        random_seed: int | None = None,
        max_outgoing_bytes: int = 1024 * 1024,
        max_pending_commands: int = 4096,
        max_messages: int = 4096,
        max_incoming_bytes: int = 4 * 1024 * 1024,
        max_subscriptions: int = 4096,
    ) -> None:
        super().__init__(
            node_id,
            max_messages=max_messages,
            max_incoming_bytes=max_incoming_bytes,
            max_subscriptions=max_subscriptions,
        )

        address = ipaddress.ip_address(host)
        if getattr(address, "scope_id", None) is not None:
            raise ValueError(
                "use an unscoped numeric IP address"
            )

        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 1 <= port <= 65535
        ):
            raise ValueError(
                "port must be between 1 and 65535"
            )

        for value in (
            reconnect_initial,
            reconnect_max,
            connect_timeout,
            heartbeat_interval,
            heartbeat_timeout,
        ):
            if (
                isinstance(value, bool)
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError(
                    "timing limits must be positive finite numbers"
                )

        if reconnect_initial > reconnect_max:
            raise ValueError(
                "initial reconnect delay exceeds its maximum"
            )

        for value in (
            max_outgoing_bytes,
            max_pending_commands,
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 1
            ):
                raise ValueError(
                    "queue limits must be positive integers"
                )

        if not callable(clock):
            raise TypeError("clock must be callable")

        if username is not None and password is None:
            raise ValueError("username requires a password")

        if password is not None:
            password.encode("utf-8", errors="strict")

        if username is not None:
            username.encode("utf-8", errors="strict")

        self._family = (
            socket.AF_INET
            if address.version == 4
            else socket.AF_INET6
        )
        self._address = (str(address), port)
        self._clock = clock
        self._password = password
        self._username = username
        self._initial_backoff = float(reconnect_initial)
        self._max_backoff = float(reconnect_max)
        self._connect_timeout = float(connect_timeout)
        self._heartbeat_interval = float(heartbeat_interval)
        self._heartbeat_timeout = float(heartbeat_timeout)
        self._max_outgoing_bytes = max_outgoing_bytes
        self._max_pending_commands = max_pending_commands
        self._random = Random(random_seed)

        self._owns_backend = backend is None
        self._owns_timers = timers is None
        self._backend = (
            create_backend()
            if backend is None
            else backend
        )
        self._timers = (
            TimerHeap()
            if timers is None
            else timers
        )
        self._scratch = bytearray(_IO_BUDGET)

        self._links = {
            role: _Link(
                role,
                backoff=self._initial_backoff,
            )
            for role in (
                LinkRole.PUBLISHER,
                LinkRole.SUBSCRIBER,
            )
        }

    @property
    def timers(self) -> TimerHeap:
        return self._timers

    @property
    def publisher_connected(self) -> bool:
        return (
            self._links[LinkRole.PUBLISHER].state
            == LinkState.READY
        )

    @property
    def subscriber_connected(self) -> bool:
        return (
            self._links[LinkRole.SUBSCRIBER].state
            == LinkState.READY
        )

    @property
    def ready(self) -> bool:
        subscriber = self._links[LinkRole.SUBSCRIBER]
        return (
            self._state == BusState.INITIALIZED
            and self.publisher_connected
            and self.subscriber_connected
            and not subscriber.controls
            and subscriber.subscribed == self._rooms
        )

    def _now(self, now: float | None = None) -> float:
        result = self._clock() if now is None else now
        if (
            isinstance(result, bool)
            or not math.isfinite(result)
        ):
            raise ValueError(
                "clock must produce finite monotonic seconds"
            )
        return float(result)

    def initialize(self) -> None:
        self._require_open()
        if self._state == BusState.NEW:
            self._state = BusState.INITIALIZED
            now = self._now()
            for link in self._links.values():
                self._connect(link, now)

    def _cancel_timers(self, link: _Link) -> None:
        for name in (
            "retry_timer",
            "connect_timer",
            "heartbeat_timer",
            "pong_timer",
        ):
            timer_id = getattr(link, name)
            if timer_id is not None:
                self._timers.cancel(timer_id)
                setattr(link, name, None)

    def _disconnect(
        self,
        link: _Link,
        now: float,
        message: str,
        *,
        error_number: int | None = None,
        reconnect: bool = True,
    ) -> None:
        self._cancel_timers(link)

        if message:
            self._record_error(
                link.role.name.lower(),
                message,
                error_number,
            )

        # Unconfirmed publications are never replayed after reconnect.
        self.publication_drops += sum(
            command.kind == CommandKind.PUBLISH
            for command in link.pending
        )

        if link.registered:
            link.registered = False
            try:
                self._backend.unregister(link.fd)
            except (OSError, KeyError, RuntimeError) as error:
                self._record_error(
                    "unregister",
                    str(error),
                )

        if link.sock is not None:
            try:
                link.sock.close()
            except OSError as error:
                # Retrying close after EINTR can close a reused descriptor.
                self._record_error(
                    "close",
                    str(error),
                    error.errno,
                )

        link.sock = None
        link.fd = -1
        link.mask = 0
        link.registration = None

        while link.outbound:
            link.outbound.popleft().release()

        link.queued_bytes = 0
        link.pending.clear()
        link.subscribed.clear()
        link.controls.clear()
        link.pong_token = None
        link.decoder.reset()

        if reconnect and self._state != BusState.CLOSED:
            link.state = LinkState.DISCONNECTED
            delay = min(
                self._max_backoff,
                link.backoff
                * self._random.uniform(0.5, 1.5),
            )
            link.backoff = min(
                self._max_backoff,
                link.backoff * 2.0,
            )
            link.retry_timer = self._timers.schedule_after(
                now,
                delay,
                partial(self._retry, link.role),
            )
        else:
            link.state = LinkState.CLOSED

    def _retry(
        self,
        role: LinkRole,
        timer_id: int,
        now: float,
    ) -> None:
        link = self._links[role]
        if (
            link.retry_timer == timer_id
            and self._state != BusState.CLOSED
        ):
            link.retry_timer = None
            self._connect(link, now)

    def _connect_timeout_fired(
        self,
        role: LinkRole,
        timer_id: int,
        now: float,
    ) -> None:
        link = self._links[role]
        if (
            link.connect_timer == timer_id
            and link.state
            in (
                LinkState.CONNECTING,
                LinkState.INITIALIZING,
            )
        ):
            link.connect_timer = None
            self._disconnect(
                link,
                now,
                "Redis connection initialization timed out",
                error_number=errno.ETIMEDOUT,
            )

    def _connect(self, link: _Link, now: float) -> None:
        if self._state == BusState.CLOSED:
            return

        candidate: socket.socket | None = None

        try:
            candidate = socket.socket(
                self._family,
                socket.SOCK_STREAM,
            )
            candidate.setblocking(False)
            candidate.setsockopt(
                socket.IPPROTO_TCP,
                socket.TCP_NODELAY,
                1,
            )

            link.sock = candidate
            link.fd = candidate.fileno()
            link.generation += 1
            link.registration = _Registration(
                self,
                link.role,
                link.generation,
            )
            link.state = LinkState.CONNECTING

            result = candidate.connect_ex(self._address)
            if (
                result not in (0, errno.EISCONN)
                and result not in _CONNECTING
            ):
                raise OSError(
                    result,
                    "Redis connect_ex failed",
                )

            self._backend.register(
                link.fd,
                READ | WRITE,
                link.registration,
            )
            link.registered = True
            link.mask = READ | WRITE
            link.connect_timer = self._timers.schedule_after(
                now,
                self._connect_timeout,
                partial(
                    self._connect_timeout_fired,
                    link.role,
                ),
            )

            if result in (0, errno.EISCONN):
                self._connected(link, now)

        except (OSError, KeyError, RuntimeError) as error:
            if candidate is not None and link.sock is None:
                try:
                    candidate.close()
                except OSError as close_error:
                    self._record_error(
                        "close",
                        str(close_error),
                        close_error.errno,
                    )

            self._disconnect(
                link,
                now,
                str(error),
                error_number=(
                    error.errno
                    if isinstance(error, OSError)
                    else None
                ),
            )

    def _sync_interest(
        self,
        link: _Link,
        now: float,
    ) -> None:
        if link.sock is None or not link.registered:
            return

        mask = READ
        if (
            link.state == LinkState.CONNECTING
            or link.outbound
        ):
            mask |= WRITE

        if mask != link.mask:
            try:
                self._backend.modify(
                    link.fd,
                    mask,
                    link.registration,
                )
            except (OSError, KeyError, RuntimeError) as error:
                self._disconnect(
                    link,
                    now,
                    str(error),
                )
                return

            link.mask = mask

    def _queue_command(
        self,
        link: _Link,
        command: _Command,
        packet: bytes,
        now: float,
    ) -> bool:
        if (
            link.sock is None
            or len(link.pending) >= self._max_pending_commands
            or len(packet)
            > self._max_outgoing_bytes - link.queued_bytes
        ):
            return False

        link.outbound.append(memoryview(packet))
        link.queued_bytes += len(packet)
        link.pending.append(command)

        if (
            command.room is not None
            and command.kind
            in (
                CommandKind.SUBSCRIBE,
                CommandKind.UNSUBSCRIBE,
            )
        ):
            link.controls[command.room] = command.kind

        self._sync_interest(link, now)
        return link.sock is not None

    def _connected(self, link: _Link, now: float) -> None:
        link.state = LinkState.INITIALIZING

        if self._password is not None:
            if self._username is None:
                packet = encode_command(
                    b"AUTH",
                    self._password,
                )
            else:
                packet = encode_command(
                    b"AUTH",
                    self._username,
                    self._password,
                )

            if not self._queue_command(
                link,
                _Command(CommandKind.AUTH),
                packet,
                now,
            ):
                if link.sock is not None:
                    self._disconnect(
                        link,
                        now,
                        "Redis AUTH queue limit reached",
                    )
                return

        if not self._queue_command(
            link,
            _Command(CommandKind.PING),
            encode_command(b"PING"),
            now,
        ):
            if link.sock is not None:
                self._disconnect(
                    link,
                    now,
                    "Redis initialization queue limit reached",
                )

    def _mark_ready(self, link: _Link, now: float) -> None:
        link.state = LinkState.READY
        link.backoff = self._initial_backoff

        if link.connect_timer is not None:
            self._timers.cancel(link.connect_timer)
            link.connect_timer = None

        link.heartbeat_timer = self._timers.schedule_after(
            now,
            self._heartbeat_interval,
            partial(self._heartbeat, link.role),
        )

        if link.role == LinkRole.SUBSCRIBER:
            self._reconcile(link, now)

    def _heartbeat(
        self,
        role: LinkRole,
        timer_id: int,
        now: float,
    ) -> None:
        link = self._links[role]
        if (
            link.heartbeat_timer != timer_id
            or link.state != LinkState.READY
        ):
            return

        link.heartbeat_timer = None
        link.ping_sequence += 1
        token = (
            f"victory:{self.node_id}:"
            f"{link.generation}:{link.ping_sequence}"
        ).encode("ascii")
        link.pong_token = token

        if not self._queue_command(
            link,
            _Command(
                CommandKind.PING,
                token=token,
            ),
            encode_command(b"PING", token),
            now,
        ):
            if link.sock is not None:
                self._disconnect(
                    link,
                    now,
                    "Redis heartbeat queue limit reached",
                )
            return

        link.pong_timer = self._timers.schedule_after(
            now,
            self._heartbeat_timeout,
            partial(self._pong_timeout, role),
        )

    def _pong_timeout(
        self,
        role: LinkRole,
        timer_id: int,
        now: float,
    ) -> None:
        link = self._links[role]
        if (
            link.pong_timer == timer_id
            and link.pong_token is not None
        ):
            link.pong_timer = None
            self._disconnect(
                link,
                now,
                "Redis heartbeat response timed out",
                error_number=errno.ETIMEDOUT,
            )

    def _reconcile(self, link: _Link, now: float) -> None:
        if (
            link.role != LinkRole.SUBSCRIBER
            or link.state != LinkState.READY
        ):
            return

        # Removing obsolete rooms first bounds server state during churn.
        phases = (
            (
                CommandKind.UNSUBSCRIBE,
                link.subscribed - self._rooms,
            ),
            (
                CommandKind.SUBSCRIBE,
                self._rooms - link.subscribed,
            ),
        )

        for kind, rooms in phases:
            for room in sorted(rooms):
                if room in link.controls:
                    continue

                verb = (
                    b"SUBSCRIBE"
                    if kind == CommandKind.SUBSCRIBE
                    else b"UNSUBSCRIBE"
                )

                if not self._queue_command(
                    link,
                    _Command(kind, room=room),
                    encode_command(
                        verb,
                        channel_for(room),
                    ),
                    now,
                ):
                    return

    def publish(
        self,
        room: str,
        deliver_payload: bytes,
    ) -> bool:
        self._require_open()
        self._publication(room, deliver_payload)
        self.initialize()

        link = self._links[LinkRole.PUBLISHER]
        if link.state != LinkState.READY:
            self.publication_drops += 1
            return False

        packet = encode_command(
            b"PUBLISH",
            channel_for(room),
            bytes((BUS_VERSION,)) + deliver_payload,
        )

        drops_before = self.publication_drops
        accepted = self._queue_command(
            link,
            _Command(CommandKind.PUBLISH),
            packet,
            self._now(),
        )

        if (
            not accepted
            and self.publication_drops == drops_before
        ):
            self.publication_drops += 1

        return accepted

    def subscribe(self, room: str) -> bool:
        self._require_open()
        validate_room(room)

        if room in self._rooms:
            return True

        if len(self._rooms) >= self._max_subscriptions:
            self._record_error(
                "subscribe",
                "subscription limit reached",
            )
            return False

        self._rooms.add(room)
        self.initialize()
        self._reconcile(
            self._links[LinkRole.SUBSCRIBER],
            self._now(),
        )
        return True

    def unsubscribe(self, room: str) -> bool:
        self._require_open()
        validate_room(room)

        if room not in self._rooms:
            return False

        self._rooms.remove(room)
        self._reconcile(
            self._links[LinkRole.SUBSCRIBER],
            self._now(),
        )
        return True

    def _reply(
        self,
        link: _Link,
        value: RespValue,
        now: float,
    ) -> None:
        if isinstance(value, RespError):
            raise RespProtocolError(
                value.message.decode(
                    "utf-8",
                    errors="replace",
                )
            )

        if (
            link.role == LinkRole.SUBSCRIBER
            and isinstance(value, list)
        ):
            if (
                len(value) == 3
                and value[0] == b"message"
            ):
                if (
                    not isinstance(value[1], bytes)
                    or not isinstance(value[2], bytes)
                ):
                    raise RespProtocolError(
                        "malformed Pub/Sub message"
                    )

                self._receive_envelope(
                    value[1],
                    value[2],
                )
                return

        if not link.pending:
            raise RespProtocolError(
                "unsolicited Redis command response"
            )

        command = link.pending[0]

        if command.kind == CommandKind.AUTH:
            if value != b"OK":
                raise RespProtocolError(
                    "Redis AUTH did not return OK"
                )

        elif command.kind == CommandKind.PUBLISH:
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                raise RespProtocolError(
                    "PUBLISH response must be a nonnegative integer"
                )

        elif command.kind == CommandKind.PING:
            expected = (
                b"PONG"
                if command.token is None
                else command.token
            )

            if isinstance(value, list):
                if (
                    link.role != LinkRole.SUBSCRIBER
                    or len(value) != 2
                    or value[0] != b"pong"
                ):
                    raise RespProtocolError(
                        "malformed subscribed PONG"
                    )
                value = value[1]

            if value != expected:
                raise RespProtocolError(
                    "Redis PONG token mismatch"
                )

        else:
            verb = (
                b"subscribe"
                if command.kind == CommandKind.SUBSCRIBE
                else b"unsubscribe"
            )

            if (
                not isinstance(value, list)
                or len(value) != 3
                or value[0] != verb
                or command.room is None
                or value[1] != channel_for(command.room)
                or not isinstance(value[2], int)
                or isinstance(value[2], bool)
            ):
                raise RespProtocolError(
                    "malformed subscription acknowledgement"
                )

            if command.kind == CommandKind.SUBSCRIBE:
                link.subscribed.add(command.room)
            else:
                link.subscribed.discard(command.room)

            if value[2] != len(link.subscribed):
                raise RespProtocolError(
                    "subscription count mismatch"
                )

            link.controls.pop(command.room, None)

        link.pending.popleft()

        if command.kind == CommandKind.PING:
            if command.token is None:
                self._mark_ready(link, now)
            else:
                if link.pong_timer is not None:
                    self._timers.cancel(link.pong_timer)
                    link.pong_timer = None

                link.pong_token = None
                link.heartbeat_timer = (
                    self._timers.schedule_after(
                        now,
                        self._heartbeat_interval,
                        partial(
                            self._heartbeat,
                            link.role,
                        ),
                    )
                )

    def _read(self, link: _Link, now: float) -> None:
        remaining = _IO_BUDGET

        for _ in range(_OPERATION_BUDGET):
            if link.sock is None or remaining == 0:
                break

            try:
                count = link.sock.recv_into(
                    self._scratch,
                    remaining,
                )
            except OSError as error:
                if error.errno == errno.EINTR:
                    continue
                if error.errno in _WOULD_BLOCK:
                    break

                self._disconnect(
                    link,
                    now,
                    str(error),
                    error_number=error.errno,
                )
                return

            if count == 0:
                self._disconnect(
                    link,
                    now,
                    "Redis closed the connection",
                )
                return

            remaining -= count
            failure: RespProtocolError | None = None

            try:
                with memoryview(self._scratch) as buf:
                    with buf[:count] as received:
                        values = link.decoder.feed(received)
            except RespProtocolError as error:
                values = error.completed_values
                failure = error

            for value in values:
                try:
                    self._reply(link, value, now)
                except RespProtocolError as error:
                    self._disconnect(
                        link,
                        now,
                        str(error),
                    )
                    return

                if link.sock is None:
                    return

            if failure is not None:
                self._disconnect(
                    link,
                    now,
                    str(failure),
                )
                return

        self._reconcile(link, now)

    def _write(self, link: _Link, now: float) -> None:
        remaining = _IO_BUDGET

        for _ in range(_OPERATION_BUDGET):
            if (
                link.sock is None
                or not link.outbound
                or remaining == 0
            ):
                break

            head = link.outbound[0]

            try:
                with head[:min(len(head), remaining)] as buf:
                    count = link.sock.send(buf)
            except OSError as error:
                if error.errno == errno.EINTR:
                    continue
                if error.errno in _WOULD_BLOCK:
                    break

                self._disconnect(
                    link,
                    now,
                    str(error),
                    error_number=error.errno,
                )
                return

            if count == 0:
                self._disconnect(
                    link,
                    now,
                    "Redis send returned zero",
                    error_number=errno.EPIPE,
                )
                return

            remaining -= count
            link.queued_bytes -= count

            if count == len(head):
                link.outbound.popleft().release()
            else:
                link.outbound[0] = head[count:]
                head.release()

        self._reconcile(link, now)
        self._sync_interest(link, now)

    def handle_event(
        self,
        event: Event,
        now: float | None = None,
    ) -> bool:
        registration = event.data

        if (
            not isinstance(registration, _Registration)
            or registration.owner is not self
        ):
            return False

        link = self._links[registration.role]

        # Immutable generation tokens prevent stale events using a reused fd.
        if (
            self._state == BusState.CLOSED
            or link.sock is None
            or event.fd != link.fd
            or registration.generation != link.generation
        ):
            return True

        current = self._now(now)

        if event.mask & (ERROR | HANGUP):
            try:
                code = link.sock.getsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_ERROR,
                )
            except OSError as error:
                code = error.errno or errno.EIO

            self._disconnect(
                link,
                current,
                "Redis readiness failure",
                error_number=code or errno.ECONNRESET,
            )
            return True

        if link.state == LinkState.CONNECTING:
            try:
                code = link.sock.getsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_ERROR,
                )
            except OSError as error:
                code = error.errno or errno.EIO

            if code:
                self._disconnect(
                    link,
                    current,
                    "Redis connection failed",
                    error_number=code,
                )
                return True

            self._connected(link, current)

        if (
            link.sock is not None
            and event.mask & (READ | PEER_CLOSED)
        ):
            self._read(link, current)

        if link.sock is not None and event.mask & WRITE:
            self._write(link, current)

        return True

    def poll(self) -> list[BusMessage]:
        if self._state == BusState.CLOSED:
            return []

        self.initialize()
        now = self._now()

        if self._owns_timers:
            self._timers.run_due(now)
            for failure in self._timers.drain_errors():
                self._record_error(
                    "timer",
                    failure.message,
                )

        if self._owns_backend:
            for event in self._backend.poll(0.0):
                self.handle_event(event, now)

        return super().poll()

    def close(self) -> None:
        if self._state == BusState.CLOSED:
            return

        self._finish_close()

        for link in self._links.values():
            self._disconnect(
                link,
                0.0,
                "",
                reconnect=False,
            )

        if self._owns_backend:
            self._backend.close()