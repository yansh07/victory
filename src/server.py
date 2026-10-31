from __future__ import annotations

import argparse
import errno
import math
import os
import socket
import struct
import sys
import threading
import time
from collections import deque
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from victory.cluster.redis_bus import RedisClusterBus
from victory.core.router import (
    Action,
    AppendWalAction,
    CloseSessionAction,
    EnqueueClientBufferAction,
    Router,
    WalMessage,
)
from victory.core.session import SessionState
from victory.lifecycle.shutdown import (
    DrainConnection,
    ShutdownCoordinator,
    ShutdownState,
)
from victory.metrics import Metric, Metrics
from victory.net.backends import Event
from victory.net.connection import Connection, ConnectionState
from victory.net.reactor import Reactor
from victory.net.timers import SessionTimers, TimerHeap
from victory.protocol.codec import (
    Deliver,
    decode_payload,
    encode_payload,
)
from victory.protocol.frame import Frame, ProtocolError
from victory.storage.wal import (
    MAX_LSN,
    WalError,
    WalRecord,
    WriteAheadLog,
    decode_message,
    encode_record,
)
from victory.storage.writer_thread import WalWriter, WriterState

MAX_PAYLOAD = 65536
READ_BUDGET = 64 * 1024
LOW_WATERMARK = 64 * 1024
SOFT_LIMIT = 256 * 1024
HARD_LIMIT = 1024 * 1024

_HEADER = struct.Struct("!HBBBBII")
_ERROR_HEADER = struct.Struct("!HBH")


def _packet(
    kind: int,
    request_id: int,
    payload: bytes,
) -> bytes:
    if len(payload) > MAX_PAYLOAD:
        raise ValueError(
            "outbound frame exceeds maximum payload"
        )

    return _HEADER.pack(
        0xCE57,
        1,
        kind,
        0,
        0,
        request_id,
        len(payload),
    ) + payload


def _error_packet(
    code: int,
    fatal: bool,
    request_id: int,
    message: str,
) -> bytes:
    text = (
        message.replace("\x00", "?")
        .encode("utf-8", "replace")[:256]
    )
    text = text.decode("utf-8", "ignore").encode("utf-8")

    payload = (
        _ERROR_HEADER.pack(code, int(fatal), len(text))
        + text
    )
    return _packet(8, request_id, payload)


@dataclass(frozen=True, slots=True)
class ServerConfig:
    node_id: int
    tokens: Sequence[str]
    wal_directory: Path
    host: str = "127.0.0.1"
    port: int = 9000
    redis_host: str = "127.0.0.1"
    redis_port: int = 6379
    max_connections: int = 10000
    max_rooms: int = 4096
    shutdown_ms: int = 5000
    loop_lag_interval: float = 1.0

    def __post_init__(self) -> None:
        for name, value, minimum, maximum in (
            ("node_id", self.node_id, 0, 0xFFFFFFFF),
            ("port", self.port, 0, 65535),
            ("redis_port", self.redis_port, 1, 65535),
            (
                "max_connections",
                self.max_connections,
                1,
                1000000,
            ),
            ("max_rooms", self.max_rooms, 1, 4096),
            ("shutdown_ms", self.shutdown_ms, 0, 5000),
        ):
            if (
                type(value) is not int
                or not minimum <= value <= maximum
            ):
                raise ValueError(f"invalid {name}")

        if isinstance(self.tokens, str) or not self.tokens:
            raise ValueError(
                "configure at least one authentication token"
            )

        for token in self.tokens:
            if (
                not isinstance(token, str)
                or not 1 <= len(token.encode("utf-8")) <= 256
                or "\x00" in token
            ):
                raise ValueError(
                    "tokens must contain 1 through 256 "
                    "UTF-8 bytes without NUL"
                )

        if (
            not math.isfinite(self.loop_lag_interval)
            or self.loop_lag_interval < 0.001
        ):
            raise ValueError(
                "loop_lag_interval must be finite and "
                "at least 0.001 seconds"
            )

        object.__setattr__(
            self,
            "tokens",
            tuple(self.tokens),
        )
        object.__setattr__(
            self,
            "wal_directory",
            Path(self.wal_directory),
        )


@dataclass(frozen=True, slots=True)
class _WalSample:
    records: int
    byte_count: int
    fsync_ns: int
    last_lsn: int


class _MeasuredWal(WriteAheadLog):
    """Measure fsync on the existing WAL-owning thread."""

    def __init__(
        self,
        directory: Path,
        replay: Callable[[WalRecord], None],
        samples: deque[_WalSample],
    ) -> None:
        self._samples = samples
        super().__init__(directory, on_replay=replay)

    def append_batch(
        self,
        records: Sequence[WalRecord],
    ) -> int:
        # M7 exposes no fsync timing hook. Preserve its poison, LSN, and
        # durability contract while timing the actual fsync operation.
        self._check_owner()

        if self._failed:
            raise WalError(
                "WAL is poisoned; restart and recover before writing"
            )

        if not records:
            raise ValueError(
                "a WAL batch must not be empty"
            )

        expected = self._last_lsn + 1
        encoded: list[bytes] = []

        for record in records:
            if (
                record.lsn != expected
                or record.lsn > MAX_LSN
            ):
                raise ValueError(
                    f"expected WAL LSN {expected}"
                )

            encoded.append(encode_record(record))
            expected += 1

        data = b"".join(encoded)

        if self._size + len(data) > self.segment_limit:
            raise WalError(
                "prepare the segment before appending a batch"
            )

        try:
            view = memoryview(data)
            offset = 0

            while offset < len(view):
                try:
                    written = os.write(
                        self._fd,
                        view[offset:],
                    )
                except InterruptedError:
                    continue

                if written <= 0:
                    raise OSError(
                        errno.EIO,
                        "WAL write made no progress",
                    )

                offset += written

            started = time.monotonic_ns()

            while True:
                try:
                    os.fsync(self._fd)
                    break
                except InterruptedError:
                    continue

            fsync_ns = time.monotonic_ns() - started

        except BaseException:
            self._failed = True
            raise

        self._size += len(data)
        self._last_lsn = records[-1].lsn
        self._samples.append(
            _WalSample(
                len(records),
                len(data),
                fsync_ns,
                self._last_lsn,
            )
        )
        return self._last_lsn


class _CountingSocket(socket.socket):
    def __init__(
        self,
        original: socket.socket,
        metrics: Metrics,
        incoming: Metric,
        outgoing: Metric,
    ) -> None:
        self._metrics = metrics
        self._incoming = incoming
        self._outgoing = outgoing

        family = original.family
        kind = original.type
        protocol = original.proto
        fd = original.detach()

        try:
            super().__init__(
                family,
                kind,
                protocol,
                fileno=fd,
            )
        except BaseException:
            os.close(fd)
            raise

        self.setblocking(False)

    def recv(
        self,
        bufsize: int,
        flags: int = 0,
    ) -> bytes:
        data = super().recv(bufsize, flags)

        if data:
            self._metrics.add(
                self._incoming,
                len(data),
            )

        return data

    def recv_into(
        self,
        buffer: Any,
        nbytes: int = 0,
        flags: int = 0,
    ) -> int:
        count = super().recv_into(
            buffer,
            nbytes,
            flags,
        )

        if count:
            self._metrics.add(
                self._incoming,
                count,
            )

        return count

    def send(
        self,
        data: Any,
        flags: int = 0,
    ) -> int:
        count = super().send(data, flags)

        if count:
            self._metrics.add(
                self._outgoing,
                count,
            )

        return count

    def sendall(
        self,
        data: Any,
        flags: int = 0,
    ) -> None:
        raise RuntimeError(
            "use non-blocking partial send operations"
        )


class _ObservedConnection(Connection):
    def __init__(
        self,
        sock: socket.socket,
        backend: Any,
        metrics: Metrics,
    ) -> None:
        self._metrics = metrics
        self._accounted = 0
        self._was_paused = False
        self._slow_reported = False
        self._reported_errors: dict[
            tuple[int, int, bool], int
        ] = {}

        super().__init__(
            sock,
            backend,
            max_payload=MAX_PAYLOAD,
            low_watermark=LOW_WATERMARK,
            soft_limit=SOFT_LIMIT,
            hard_limit=HARD_LIMIT,
        )

    def _sync_metrics(self) -> None:
        current = self.queued_bytes
        delta = current - self._accounted

        if delta:
            self._metrics.adjust(
                Metric.OUTBOUND_BYTES,
                delta,
            )
            self._accounted = current
            total = self._metrics.get(
                Metric.OUTBOUND_BYTES
            )

            if total > self._metrics.get(
                Metric.OUTBOUND_PEAK
            ):
                self._metrics.set(
                    Metric.OUTBOUND_PEAK,
                    total,
                )

        paused = self.read_paused

        if self.state == ConnectionState.OPEN:
            if paused and not self._was_paused:
                self._metrics.add(
                    Metric.READ_PAUSES
                )
            elif self._was_paused and not paused:
                self._metrics.add(
                    Metric.READ_RESUMES
                )

        self._was_paused = paused

    def queue_bytes(
        self,
        data: bytes | bytearray | memoryview,
    ) -> bool:
        if (
            self.state != ConnectionState.CLOSED
            and self.queued_bytes + len(data) > HARD_LIMIT
            and not self._slow_reported
        ):
            self._slow_reported = True
            self._metrics.add(
                Metric.SLOW_CONSUMERS
            )

        try:
            accepted = super().queue_bytes(data)

            if (
                accepted
                and len(data) >= 17
                and data[3] == 8
                and data[0] == 0xCE
                and data[1] == 0x57
            ):
                request_id = struct.unpack_from(
                    "!I",
                    data,
                    6,
                )[0]
                code, fatal = struct.unpack_from(
                    "!HB",
                    data,
                    14,
                )
                key = (
                    request_id,
                    code,
                    bool(fatal),
                )
                self._reported_errors[key] = (
                    self._reported_errors.get(key, 0) + 1
                )

            return accepted

        finally:
            self._sync_metrics()

    def handle_events(
        self,
        mask: int,
        scratch: bytearray,
    ) -> list[Frame]:
        try:
            return super().handle_events(
                mask,
                scratch,
            )
        finally:
            self._sync_metrics()

    def close(self) -> None:
        try:
            super().close()
        finally:
            self._sync_metrics()

    def error_already_queued(
        self,
        request_id: int,
        code: int,
        fatal: bool,
    ) -> bool:
        key = (request_id, code, fatal)
        count = self._reported_errors.get(key, 0)

        if not count:
            return False

        if count == 1:
            del self._reported_errors[key]
        else:
            self._reported_errors[key] = count - 1

        return True


@dataclass(slots=True)
class _Client:
    fd: int
    session_id: int
    connection: _ObservedConnection
    reactor_record: Any
    rooms: frozenset[str] = frozenset()


@dataclass(frozen=True, slots=True)
class _BusTag:
    data: object


class _BusBackend:
    """Namespace Redis readiness without taking ownership of the poller."""

    def __init__(
        self,
        backend: _RoutingBackend,
    ) -> None:
        self._backend = backend
        self._registrations: dict[int, object] = {}

    def register(
        self,
        fd: int,
        mask: int,
        data: object = None,
    ) -> None:
        self._backend.register(
            fd,
            mask,
            _BusTag(data),
        )
        self._registrations[fd] = data

    def modify(
        self,
        fd: int,
        mask: int,
        data: object = None,
    ) -> None:
        original = (
            self._registrations.get(fd)
            if data is None
            else data
        )
        self._backend.modify(
            fd,
            mask,
            _BusTag(original),
        )
        self._registrations[fd] = original

    def unregister(self, fd: int) -> None:
        self._backend.unregister(fd)
        self._registrations.pop(fd, None)

    def poll(
        self,
        timeout: float | None,
    ) -> list[Event]:
        raise RuntimeError(
            "the master reactor exclusively owns backend polling"
        )

    def close(self) -> None:
        for fd in list(self._registrations):
            self.unregister(fd)


class _RoutingBackend:
    def __init__(
        self,
        backend: Any,
        server: Server,
    ) -> None:
        self.raw = backend
        self.server = server

    def register(
        self,
        fd: int,
        mask: int,
        data: object = None,
    ) -> None:
        self.raw.register(fd, mask, data)

    def modify(
        self,
        fd: int,
        mask: int,
        data: object = None,
    ) -> None:
        self.raw.modify(fd, mask, data)

    def unregister(self, fd: int) -> None:
        self.raw.unregister(fd)

    def poll(
        self,
        timeout: float | None,
    ) -> list[Event]:
        events = self.raw.poll(timeout)
        self.server._synchronize_clients()
        remaining: list[Event] = []

        for event in events:
            self.server._before_event()

            if self.server.shutdown.finished:
                return []

            if (
                event.data is self.server.shutdown
                or event.data is self.server.writer
            ):
                self.server.shutdown.handle_event(event)
                self.server._enter_draining()

            elif isinstance(event.data, _BusTag):
                original = Event(
                    event.fd,
                    event.mask,
                    event.data.data,
                )
                self.server._bus_event(original)

            elif event.fd == self.server._listener_fd:
                if (
                    self.server.shutdown.state
                    == ShutdownState.RUNNING
                ):
                    remaining.append(event)

            elif event.fd in self.server._by_fd:
                self.server._connection_event(event)

            elif isinstance(event.data, Connection):
                continue

            else:
                remaining.append(event)

        if self.server.shutdown.finished:
            return []

        return remaining

    def close(self) -> None:
        self.raw.close()


class _DurabilityRouter:
    """Adapt the coordinator's completion port to the pure core."""

    def __init__(self, server: Server) -> None:
        self.server = server

    @property
    def pending_count(self) -> int:
        return self.server.router.pending_count

    def wal_committed(
        self,
        commit_id: int,
    ) -> list[Action]:
        actions = self.server.router.wal_committed(
            commit_id
        )
        record = self.server._pending_records.pop(
            commit_id,
            None,
        )

        if record is not None:
            payload = encode_payload(
                Deliver(
                    room=record.room,
                    origin_node=record.origin_node,
                    seq=record.seq,
                    sender=record.user,
                    client_msg_id=record.client_msg_id,
                    body=record.body,
                )
            )
            self.server._publications.append(
                (record.room, payload)
            )
            self.server._publication_bytes += len(payload)

        return actions

    def wal_failed(
        self,
        commit_id: int,
        message: str,
    ) -> list[Action]:
        self.server._note_wal_failure()
        self.server._pending_records.clear()
        self.server._admissions.clear()

        return self.server.router.wal_failed(
            commit_id,
            message,
        )

    def begin_shutdown(
        self,
        deadline_ms: int = 0,
    ) -> list[Action]:
        self.server._note_wal_failure()
        return self.server.router.begin_shutdown(
            deadline_ms
        )


class Server:
    def __init__(self, config: ServerConfig) -> None:
        if (
            threading.current_thread()
            is not threading.main_thread()
        ):
            raise RuntimeError(
                "the server and its signal handlers "
                "run on the main thread"
            )

        self.config = config
        self.metrics = Metrics()
        self._owner = threading.get_ident()

        self._closed = False
        self._running = False
        self._entered_draining = False
        self._bus_draining = False
        self._bus_closed = False
        self._wal_failed = False
        self._exit_status = 0

        self._scratch = bytearray(READ_BUDGET)
        self._by_fd: dict[int, _Client] = {}
        self._by_session: dict[int, _Client] = {}
        self._bindings: dict[int, DrainConnection] = {}
        self._room_counts: dict[str, int] = {}
        self._pending_records: dict[int, WalMessage] = {}
        self._admissions: deque[AppendWalAction] = deque()
        self._publications: deque[
            tuple[str, bytes]
        ] = deque()
        self._publication_bytes = 0
        self._wal_samples: deque[_WalSample] = deque(
            maxlen=4096
        )
        self._lag_timer: int | None = None
        self._lag_expected = 0.0

        self.timers = TimerHeap()
        self.router = Router(
            config.node_id,
            tokens=config.tokens,
            max_sessions=config.max_connections,
            max_pending=4096,
        )

        try:
            self.log = _MeasuredWal(
                config.wal_directory,
                lambda record: self.router.restore_record(
                    decode_message(record)
                ),
                self._wal_samples,
            )
            self.metrics.set(
                Metric.WAL_RECOVERED,
                self.log.recovery.record_count,
            )
            self.metrics.set(
                Metric.WAL_DURABLE_LSN,
                self.log.recovery.last_lsn,
            )

            listen_ip = self._resolve_ipv4(
                config.host,
                config.port,
            )
            redis_ip = self._resolve_ipv4(
                config.redis_host,
                config.redis_port,
            )

            listener = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM,
            )
            listener.setblocking(False)
            self.listener = listener
            listener.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_REUSEADDR,
                1,
            )
            listener.bind(
                (listen_ip, config.port)
            )
            listener.listen(
                min(
                    config.max_connections,
                    socket.SOMAXCONN,
                )
            )
            self._listener_fd = listener.fileno()

            self.reactor = Reactor(
                listener,
                on_frame=self._unexpected_frame,
                max_connections=config.max_connections,
            )
            self.backend = _RoutingBackend(
                self.reactor._backend,
                self,
            )
            self.reactor._backend = self.backend

            self._bus_backend = _BusBackend(
                self.backend
            )
            self.bus = RedisClusterBus(
                config.node_id,
                redis_ip,
                config.redis_port,
                backend=self._bus_backend,
                timers=self.timers,
            )
            self.bus.initialize()
            self._instrument_bus_sockets()

            self._bindings[0] = DrainConnection(
                session_id=0,
                fileno=lambda: -1,
                pending_bytes=self._bus_pending_output,
                enqueue=self._begin_bus_drain,
                close=self._close_bus,
            )

            self.writer = WalWriter(
                self.log,
                self.backend,
                max_pending_records=4096,
                max_pending_bytes=64 * 1024 * 1024,
            )
            self.writer.start()

            self.session_timers = SessionTimers(
                self.timers,
                self.router,
                self._apply_actions,
            )
            self._durability = _DurabilityRouter(self)

            self.shutdown = ShutdownCoordinator(
                self.backend,
                self.writer,
                self._durability,
                self._bindings,
                [listener],
                apply_actions=self._apply_actions,
                flush_pending_wal=self._admit_wal,
                on_exit=self._shutdown_complete,
                timeout_ms=config.shutdown_ms,
            )

            self._lag_expected = (
                time.monotonic()
                + config.loop_lag_interval
            )
            self._lag_timer = self.timers.schedule(
                self._lag_expected,
                self._lag_fired,
            )

        except BaseException:
            self.close()
            raise

    @staticmethod
    def _resolve_ipv4(host: str, port: int) -> str:
        # DNS belongs to boot, never to the active reconnect path.
        addresses = socket.getaddrinfo(
            host,
            port,
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
        )

        if not addresses:
            raise ValueError(
                f"no IPv4 address for {host!r}"
            )

        return addresses[0][4][0]

    @property
    def address(self) -> tuple[str, int]:
        host, port = self.listener.getsockname()
        return host, port

    def _check_owner(self) -> None:
        if threading.get_ident() != self._owner:
            raise RuntimeError(
                "application state belongs to the reactor thread"
            )

    def _unexpected_frame(
        self,
        reactor: Reactor,
        fd: int,
        frame: Frame,
    ) -> None:
        raise RuntimeError(
            "client readiness bypassed "
            "the M3 Connection dispatcher"
        )

    def _reject_socket(self, fd: int) -> None:
        self.reactor.close_connection(fd)
        self.metrics.add(Metric.ACCEPTED)
        self.metrics.add(Metric.CLOSED)
        self.metrics.add(Metric.REJECTED)

    def _synchronize_clients(self) -> None:
        if self.shutdown.signal_count >= 2:
            self.shutdown.tick()

        for entry in list(self._by_fd.values()):
            if (
                self.reactor._clients.get(entry.fd)
                is not entry.reactor_record
                or (
                    entry.connection.state
                    == ConnectionState.CLOSED
                )
            ):
                self._close_client(entry.session_id)

        for fd, record in list(
            self.reactor._clients.items()
        ):
            if fd in self._by_fd:
                continue

            if (
                self.shutdown.state
                != ShutdownState.RUNNING
            ):
                self._reject_socket(fd)
                continue

            session_id: int | None = None

            try:
                session_id = (
                    self.router.open_session().session_id
                )
                self.backend.unregister(fd)

                sock = _CountingSocket(
                    record.sock,
                    self.metrics,
                    Metric.CLIENT_BYTES_IN,
                    Metric.CLIENT_BYTES_OUT,
                )
                record.sock = sock

                connection = _ObservedConnection(
                    sock,
                    self.backend,
                    self.metrics,
                )

            except Exception:
                if session_id is not None:
                    self.router.disconnect(session_id)

                self._reject_socket(fd)
                continue

            entry = _Client(
                fd,
                session_id,
                connection,
                record,
            )
            self._by_fd[fd] = entry
            self._by_session[session_id] = entry

            self._bindings[session_id] = DrainConnection(
                session_id,
                connection.fileno,
                lambda connection=connection:
                    connection.queued_bytes,
                lambda packet, sid=session_id:
                    self._queue(sid, packet),
                lambda sid=session_id:
                    self._close_client(sid),
            )

            self.metrics.opened()
            self.session_timers.track_handshake(
                session_id,
                time.monotonic(),
            )

    def _update_rooms(self, entry: _Client) -> None:
        current = frozenset(
            self.router.rooms.rooms_for(
                entry.session_id
            )
        )

        for room in entry.rooms - current:
            count = self._room_counts[room] - 1

            if count:
                self._room_counts[room] = count
            else:
                del self._room_counts[room]
                self._unsubscribe(room)

        for room in current - entry.rooms:
            count = self._room_counts.get(room, 0)
            self._room_counts[room] = count + 1

            if not count and not self._bus_draining:
                self._subscribe(room)

        entry.rooms = current

    def _close_client(self, session_id: int) -> None:
        entry = self._by_session.pop(
            session_id,
            None,
        )

        if entry is None:
            return

        self._by_fd.pop(entry.fd, None)
        self._bindings.pop(session_id, None)
        self.session_timers.remove(session_id)

        for room in entry.rooms:
            count = self._room_counts[room] - 1

            if count:
                self._room_counts[room] = count
            else:
                del self._room_counts[room]
                self._unsubscribe(room)

        entry.rooms = frozenset()
        self.router.disconnect(session_id)

        try:
            entry.connection.close()
        finally:
            if (
                self.reactor._clients.get(entry.fd)
                is entry.reactor_record
            ):
                self.reactor.close_connection(
                    entry.fd
                )

            self.metrics.closed()

    def _queue(
        self,
        session_id: int,
        packet: bytes,
    ) -> None:
        entry = self._by_session.get(session_id)

        if (
            entry is None
            or (
                entry.connection.state
                == ConnectionState.CLOSED
            )
        ):
            return

        if entry.connection.queue_bytes(packet):
            self.metrics.add(
                Metric.FRAMES_QUEUED
            )

        if (
            entry.connection.state
            == ConnectionState.CLOSED
        ):
            self._close_client(session_id)

    def _apply_actions(
        self,
        actions: list[Action],
    ) -> None:
        for action in actions:
            if isinstance(action, AppendWalAction):
                commit_id = action.record.commit_id

                if commit_id in self._pending_records:
                    raise RuntimeError(
                        "duplicate WAL append intent"
                    )

                self._pending_records[commit_id] = (
                    action.record
                )
                self._admissions.append(action)

            elif isinstance(
                action,
                EnqueueClientBufferAction,
            ):
                self._queue(
                    action.session_id,
                    action.packet,
                )

            elif isinstance(
                action,
                CloseSessionAction,
            ):
                entry = self._by_session.get(
                    action.session_id
                )

                if entry is not None:
                    self._update_rooms(entry)

                    if action.after_flush:
                        entry.connection.close_after_flush()

                        if (
                            entry.connection.state
                            == ConnectionState.CLOSED
                        ):
                            self._close_client(
                                action.session_id
                            )
                    else:
                        self._close_client(
                            action.session_id
                        )

            else:
                raise TypeError(
                    "unsupported application action: "
                    f"{type(action).__name__}"
                )

        self._admit_wal()

    def _admit_wal(self) -> None:
        self._collect_wal_samples()

        if (
            self._wal_failed
            or self.writer.state != WriterState.RUNNING
        ):
            return

        while self._admissions:
            action = self._admissions[0]

            if not self.writer.submit(action):
                return

            self._admissions.popleft()

    def _note_wal_failure(self) -> None:
        if not self._wal_failed:
            self._wal_failed = True
            self.metrics.add(
                Metric.WAL_FAILURES
            )

    def _protocol_errors(
        self,
        entry: _Client,
    ) -> bool:
        errors = entry.connection.drain_errors()
        fatal_seen = False

        self.metrics.add(
            Metric.PROTOCOL_ERRORS,
            len(errors),
        )

        for error in errors:
            if (
                entry.session_id not in self._by_session
                or (
                    entry.connection.state
                    == ConnectionState.CLOSED
                )
            ):
                return True

            session = self.router.get_session(
                entry.session_id
            )
            fatal = bool(
                error.fatal
                or session.state == SessionState.HANDSHAKE
            )
            fatal_seen = fatal_seen or fatal

            request_id = error.request_id or 0
            code = int(error.code)

            if not entry.connection.error_already_queued(
                request_id,
                code,
                fatal,
            ):
                self._queue(
                    entry.session_id,
                    _error_packet(
                        code,
                        fatal,
                        request_id,
                        str(error),
                    ),
                )

            if fatal:
                entry.connection.close_after_flush()

        return fatal_seen

    def _connection_event(self, event: Event) -> None:
        entry = self._by_fd.get(event.fd)

        if entry is None:
            return

        connection = entry.connection

        try:
            frames = connection.handle_events(
                event.mask,
                self._scratch,
            )

            if (
                connection.state
                == ConnectionState.CLOSED
            ):
                self._close_client(
                    entry.session_id
                )
                return

            if self._protocol_errors(entry):
                return

            for frame in frames:
                self._before_event()

                if (
                    entry.session_id
                    not in self._by_session
                ):
                    break

                if (
                    connection.state
                    != ConnectionState.OPEN
                ):
                    break

                self.metrics.add(
                    Metric.FRAMES_IN
                )
                self._frame(entry, frame)

        except OSError:
            self._close_client(
                entry.session_id
            )

        finally:
            connection._reported_errors.clear()

            if (
                connection.state
                == ConnectionState.CLOSED
            ):
                self._close_client(
                    entry.session_id
                )

    def _frame(
        self,
        entry: _Client,
        frame: Frame,
    ) -> None:
        session_id = entry.session_id
        session = self.router.get_session(
            session_id
        )
        before = session.state

        self.shutdown.dispatch_command(
            session_id,
            int(frame.type),
            frame.request_id,
            lambda: self._route(entry, frame),
        )

        if session_id not in self._by_session:
            return

        session = self.router.get_session(
            session_id
        )
        now = time.monotonic()

        if (
            before == SessionState.HANDSHAKE
            and session.state == SessionState.ACTIVE
        ):
            self.session_timers.handshake_completed(
                session_id,
                now,
            )

        elif (
            before == SessionState.ACTIVE
            and session.state == SessionState.ACTIVE
        ):
            self.session_timers.note_activity(
                session_id,
                now,
            )

        if (
            int(frame.type) in (2, 3, 9)
            or session.state != before
        ):
            self._update_rooms(entry)

    def _route(
        self,
        entry: _Client,
        frame: Frame,
    ) -> list[Action]:
        session = self.router.get_session(
            entry.session_id
        )

        if (
            session.state == SessionState.ACTIVE
            and int(frame.type) == 12
        ):
            if frame.payload:
                self._queue(
                    entry.session_id,
                    _error_packet(
                        5,
                        False,
                        frame.request_id,
                        "STATS payload must be empty",
                    ),
                )
            else:
                self._collect_wal_samples()
                self.metrics.set(
                    Metric.WAL_PENDING,
                    self.writer.pending_count,
                )
                self.metrics.set(
                    Metric.SHUTDOWN_STATE,
                    int(self.shutdown.state),
                )
                payload = self.metrics.render().encode(
                    "utf-8"
                )
                self._queue(
                    entry.session_id,
                    _packet(
                        13,
                        frame.request_id,
                        payload,
                    ),
                )

            return []

        if (
            session.state == SessionState.ACTIVE
            and int(frame.type) == 2
        ):
            try:
                room = getattr(
                    decode_payload(
                        frame.type,
                        frame.payload,
                    ),
                    "room",
                )
            except ProtocolError:
                return self.router.route(
                    entry.session_id,
                    frame,
                )

            if (
                room not in self._room_counts
                and (
                    len(self._room_counts)
                    >= self.config.max_rooms
                )
            ):
                self._queue(
                    entry.session_id,
                    _error_packet(
                        12,
                        False,
                        frame.request_id,
                        "node room limit reached",
                    ),
                )
                return []

        return self.router.route(
            entry.session_id,
            frame,
        )

    def _before_event(self) -> None:
        if (
            self.shutdown.signal_count >= 2
            or (
                self.shutdown.state
                == ShutdownState.RUNNING
                and self.shutdown.signal_count
            )
        ):
            self.shutdown.tick()

        deadline = self.shutdown.deadline

        if (
            deadline is not None
            and not self.shutdown.finished
            and time.monotonic() >= deadline
        ):
            self.shutdown.tick()

        self._enter_draining()

    def _enter_draining(self) -> None:
        if (
            self._entered_draining
            or (
                self.shutdown.state
                == ShutdownState.RUNNING
            )
        ):
            return

        self._entered_draining = True

        # M2 can schedule an accept retry after resource exhaustion.
        # M8 has closed the listener, so that retry must be cancelled.
        self.reactor._accept_resume_at = None

        for session_id in list(self._by_session):
            self.session_timers.remove(
                session_id
            )

        actions = self.router.begin_shutdown(
            self.config.shutdown_ms
        )

        # The coordinator already broadcast the client SHUTDOWN packet.
        remaining = [
            action
            for action in actions
            if not (
                isinstance(
                    action,
                    EnqueueClientBufferAction,
                )
                and int(action.frame.type) == 9
            )
        ]
        self._apply_actions(remaining)

    def _begin_bus_drain(
        self,
        packet: bytes,
    ) -> None:
        # Redis sockets receive Redis commands, not Victory SHUTDOWN frames.
        # This binding instead stops new remote delivery and subscriptions.
        self._bus_draining = True
        self._reconcile_subscriptions()

    def _bus_pending_output(self) -> int:
        if self._bus_closed:
            return 0

        return (
            self._publication_bytes
            + sum(
                link.queued_bytes
                for link in self.bus._links.values()
            )
        )

    def _close_bus(self) -> None:
        if self._bus_closed:
            return

        self._bus_closed = True
        self.metrics.add(
            Metric.BUS_DROPPED,
            len(self._publications),
        )
        self._publications.clear()
        self._publication_bytes = 0

        self.bus.close()
        self._bus_backend.close()

        self.metrics.set(
            Metric.BUS_PUBLISHER_CONNECTED,
            0,
        )
        self.metrics.set(
            Metric.BUS_SUBSCRIBER_CONNECTED,
            0,
        )
        self._bindings.pop(0, None)

    def _subscribe(self, room: str) -> None:
        if self._bus_closed:
            return

        try:
            self.bus.subscribe(room)
        except Exception:
            self.metrics.add(
                Metric.BUS_ERRORS
            )

    def _unsubscribe(self, room: str) -> None:
        if self._bus_closed:
            return

        try:
            self.bus.unsubscribe(room)
        except Exception:
            self.metrics.add(
                Metric.BUS_ERRORS
            )

    def _reconcile_subscriptions(self) -> None:
        if self._bus_closed:
            return

        desired = (
            set()
            if self._bus_draining
            else set(self._room_counts)
        )
        current = self.bus.subscriptions

        for room in current - desired:
            self._unsubscribe(room)

        for room in desired - current:
            self._subscribe(room)

    def _instrument_bus_sockets(self) -> None:
        if self._bus_closed:
            return

        for link in self.bus._links.values():
            if (
                link.sock is not None
                and not isinstance(
                    link.sock,
                    _CountingSocket,
                )
            ):
                link.sock = _CountingSocket(
                    link.sock,
                    self.metrics,
                    Metric.BUS_BYTES_IN,
                    Metric.BUS_BYTES_OUT,
                )

    def _bus_event(self, event: Event) -> None:
        if self._bus_closed:
            return

        try:
            self.bus.handle_event(
                event,
                time.monotonic(),
            )
        except Exception:
            self.metrics.add(
                Metric.BUS_ERRORS
            )

        self._drain_bus()

    def _drain_bus(self) -> None:
        if self._bus_closed:
            return

        try:
            messages = self.bus.poll()
        except Exception:
            self.metrics.add(
                Metric.BUS_ERRORS
            )
            return

        for message in messages:
            if (
                self._bus_draining
                or (
                    message.origin_node
                    == self.config.node_id
                )
                or message.room != message.deliver.room
            ):
                self.metrics.add(
                    Metric.BUS_DROPPED
                )
                continue

            packet = _packet(
                10,
                0,
                message.deliver_payload,
            )
            self.metrics.add(
                Metric.BUS_RECEIVED
            )

            for session_id in tuple(
                self.router.rooms.members(
                    message.room
                )
            ):
                self._queue(
                    session_id,
                    packet,
                )

    def _flush_publications(self) -> None:
        while (
            self._publications
            and not self._bus_closed
        ):
            room, payload = self._publications.popleft()
            self._publication_bytes -= len(payload)

            try:
                accepted = self.bus.publish(
                    room,
                    payload,
                )
            except Exception:
                self.metrics.add(
                    Metric.BUS_ERRORS
                )
                accepted = False

            self.metrics.add(
                Metric.BUS_PUBLISHED
                if accepted
                else Metric.BUS_DROPPED
            )

    def _collect_wal_samples(self) -> None:
        while True:
            try:
                sample = self._wal_samples.popleft()
            except IndexError:
                return

            self.metrics.observe_wal_batch(
                sample.records,
                sample.byte_count,
                sample.fsync_ns,
                sample.last_lsn,
            )

    def _lag_fired(
        self,
        timer_id: int,
        now: float,
    ) -> None:
        if timer_id != self._lag_timer:
            return

        expected = self._lag_expected
        actual = time.monotonic()

        self.metrics.observe_loop_lag(
            int(expected * 1000000000),
            int(actual * 1000000000),
        )
        self._reconcile_subscriptions()

        interval = self.config.loop_lag_interval
        skipped = max(
            1,
            int((actual - expected) // interval) + 1,
        )
        self._lag_expected = (
            expected + skipped * interval
        )
        self._lag_timer = self.timers.schedule(
            self._lag_expected,
            self._lag_fired,
        )

    def _shutdown_complete(self, status: int) -> None:
        self._exit_status = status
        self.metrics.set(
            Metric.SHUTDOWN_STATE,
            int(ShutdownState.EXIT),
        )
        self.reactor.stop()

    def _maintenance(self) -> None:
        self._before_event()

        if self.shutdown.finished:
            return

        self._synchronize_clients()

        count = self.timers.run_due(
            time.monotonic(),
            max_events=1024,
        )
        self.metrics.add(
            Metric.TIMER_CALLBACKS,
            count,
        )

        self._instrument_bus_sockets()
        self._drain_bus()
        self.shutdown.tick()
        self._enter_draining()
        self._admit_wal()
        self._collect_wal_samples()
        self._flush_publications()
        self._synchronize_clients()

        self.metrics.set(
            Metric.WAL_PENDING,
            self.writer.pending_count,
        )
        self.metrics.set(
            Metric.SHUTDOWN_STATE,
            int(self.shutdown.state),
        )

        if not self._bus_closed:
            self.metrics.set(
                Metric.BUS_PUBLISHER_CONNECTED,
                int(self.bus.publisher_connected),
            )
            self.metrics.set(
                Metric.BUS_SUBSCRIBER_CONNECTED,
                int(self.bus.subscriber_connected),
            )

    def run(self) -> int:
        self._check_owner()

        if self._closed or self._running:
            raise RuntimeError(
                "server cannot be started in its current state"
            )

        self._running = True

        try:
            while not self.shutdown.finished:
                self._maintenance()

                if self.shutdown.finished:
                    break

                now = time.monotonic()
                timer_timeout = (
                    self.timers.get_next_timeout(now)
                )
                shutdown_timeout = (
                    self.shutdown.get_next_timeout(now)
                )

                if timer_timeout is None:
                    timeout = shutdown_timeout
                elif shutdown_timeout is None:
                    timeout = timer_timeout
                else:
                    timeout = min(
                        timer_timeout,
                        shutdown_timeout,
                    )

                self.reactor.run_once(
                    timeout=timeout
                )
                self.metrics.add(
                    Metric.LOOP_PASSES
                )

            return self._exit_status

        finally:
            self._running = False
            self.close()

    def close(self) -> None:
        self._check_owner()

        if self._closed:
            return

        self._closed = True

        shutdown = getattr(
            self,
            "shutdown",
            None,
        )
        if shutdown is not None:
            shutdown.close()

        if self._lag_timer is not None:
            self.timers.cancel(
                self._lag_timer
            )
            self._lag_timer = None

        if hasattr(self, "bus"):
            self._close_bus()

        writer = getattr(
            self,
            "writer",
            None,
        )

        if writer is not None:
            # Waiting is restricted to cleanup after the active loop exits.
            if not writer.close(
                self.config.shutdown_ms / 1000.0
            ):
                os._exit(1)

            writer.drain_completions()
            self._collect_wal_samples()

        elif hasattr(self, "log"):
            self.log.close()

        for session_id in list(self._by_session):
            self._close_client(
                session_id
            )

        if hasattr(self, "reactor"):
            self.reactor.close()
        elif hasattr(self, "listener"):
            self.listener.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Victory Engine TCP server"
    )
    parser.add_argument(
        "--node-id",
        type=int,
        required=True,
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=9000,
    )
    parser.add_argument(
        "--redis-host",
        default="127.0.0.1",
    )
    parser.add_argument(
        "--redis-port",
        type=int,
        default=6379,
    )
    parser.add_argument(
        "--wal-dir",
        type=Path,
    )
    parser.add_argument(
        "--token",
        action="append",
    )
    parser.add_argument(
        "--max-connections",
        type=int,
        default=10000,
    )
    parser.add_argument(
        "--shutdown-ms",
        type=int,
        default=5000,
    )

    arguments = parser.parse_args(argv)
    tokens = arguments.token

    if not tokens:
        token = os.environ.get(
            "VICTORY_TOKEN"
        )
        if not token:
            parser.error(
                "set VICTORY_TOKEN or provide --token"
            )
        tokens = [token]

    try:
        config = ServerConfig(
            node_id=arguments.node_id,
            tokens=tokens,
            wal_directory=(
                arguments.wal_dir
                or Path("var/victory")
                / str(arguments.node_id)
            ),
            host=arguments.host,
            port=arguments.port,
            redis_host=arguments.redis_host,
            redis_port=arguments.redis_port,
            max_connections=arguments.max_connections,
            shutdown_ms=arguments.shutdown_ms,
        )
        return Server(config).run()

    except KeyboardInterrupt:
        return 1

    except Exception as exc:
        print(
            f"victory: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())