"""Single-threaded, level-triggered reactor with an M2 framed echo default."""

from __future__ import annotations

import errno
import logging
import socket
import time
from collections import deque
from dataclasses import dataclass, field
from enum import IntEnum
from struct import Struct
from types import TracebackType
from typing import Callable, TypeAlias, cast

from ..protocol.decoder import FrameDecoder
from ..protocol.frame import Frame, FrameType, ProtocolError
from .backends import (
    ERROR,
    HANGUP,
    PEER_CLOSED,
    READ,
    WRITE,
    Backend,
    create_backend,
)

ACCEPT_BUDGET = 64
READ_BUDGET = 64 * 1024
WRITE_BUDGET = 64 * 1024
IO_OPERATION_BUDGET = 64

OUTBOUND_LOW_LIMIT = 64 * 1024
OUTBOUND_SOFT_LIMIT = 256 * 1024
OUTBOUND_HARD_LIMIT = 1024 * 1024

_ACCEPT_RETRY_DELAY = 0.25
_ERROR_PREFIX = Struct("!HBH")
_LOGGER = logging.getLogger(__name__)

_WOULD_BLOCK = frozenset(
    (errno.EAGAIN, errno.EWOULDBLOCK)
)
_DISCONNECTED = frozenset(
    (errno.ECONNRESET, errno.EPIPE, errno.ETIMEDOUT)
)
_RESOURCE_ERRORS = frozenset(
    (errno.EMFILE, errno.ENFILE, errno.ENOBUFS, errno.ENOMEM)
)
_TRANSIENT_ACCEPT_ERRORS = frozenset(
    getattr(errno, name)
    for name in (
        "ECONNABORTED",
        "ECONNRESET",
        "ENETDOWN",
        "EPROTO",
        "ENOPROTOOPT",
        "EHOSTDOWN",
        "ENONET",
        "EHOSTUNREACH",
        "EOPNOTSUPP",
        "ENETUNREACH",
        "ETIMEDOUT",
    )
    if hasattr(errno, name)
)

FrameHandler: TypeAlias = Callable[["Reactor", int, Frame], None]


class ReactorState(IntEnum):
    READY = 1
    RUNNING = 2
    STOPPING = 3
    CLOSED = 4


class _ClientState(IntEnum):
    OPEN = 1
    DRAINING = 2
    CLOSED = 3


@dataclass(slots=True, eq=False)
class _Client:
    sock: socket.socket
    fd: int
    decoder: FrameDecoder = field(default_factory=FrameDecoder)
    outbound: deque[memoryview] = field(default_factory=deque)
    queued_bytes: int = 0
    mask: int = READ
    read_paused: bool = False
    state: _ClientState = _ClientState.OPEN
    feed: Callable[[memoryview], list[Frame]] = field(
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        # M1 accepts buffers at runtime despite its bytes-only annotation.
        self.feed = cast(
            Callable[[memoryview], list[Frame]],
            self.decoder.feed,
        )


def _close_socket(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError as error:
        # Retrying close after EINTR can close a subsequently reused fd.
        _LOGGER.debug("socket close failed: %s", error)


class Reactor:
    """Own a listening socket and backend under one event-loop owner.

    The supplied listener must already be bound and listening.

    Without on_frame, complete frames are echoed. A custom handler queues
    output through send_frame() or send_bytes(). Session authentication
    and command routing belong above the M2 transport layer.

    run_forever() closes all owned resources when it exits.
    """

    def __init__(
        self,
        server: socket.socket,
        *,
        backend: Backend | None = None,
        on_frame: FrameHandler | None = None,
        max_connections: int = 10_000,
    ) -> None:
        if (
            isinstance(max_connections, bool)
            or not isinstance(max_connections, int)
            or max_connections < 1
        ):
            raise ValueError(
                "max_connections must be a positive integer"
            )

        server.setblocking(False)
        if not server.getsockopt(
            socket.SOL_SOCKET,
            socket.SO_ACCEPTCONN,
        ):
            raise ValueError("server must already be listening")

        self._backend = (
            create_backend() if backend is None else backend
        )
        self._server = server
        self._server_fd = server.fileno()
        self._on_frame = on_frame
        self._max_connections = max_connections

        self._clients: dict[int, _Client] = {}
        self._state = ReactorState.READY
        self._in_poll = False

        self._scratch = bytearray(READ_BUDGET)
        self._read_view = memoryview(self._scratch)

        self._listener_token = object()
        self._wakeup_token = object()
        self._wake_reader: socket.socket | None = None
        self._wake_writer: socket.socket | None = None
        self._accept_resume_at: float | None = None

        try:
            self._wake_reader, self._wake_writer = socket.socketpair()
            self._wake_reader.setblocking(False)
            self._wake_writer.setblocking(False)

            self._backend.register(
                self._wake_reader.fileno(),
                READ,
                self._wakeup_token,
            )
            self._backend.register(
                self._server_fd,
                READ,
                self._listener_token,
            )
        except BaseException:
            self.close()
            raise

    @classmethod
    def listen(
        cls,
        host: str = "127.0.0.1",
        port: int = 0,
        *,
        family: socket.AddressFamily = socket.AF_INET,
        backlog: int = socket.SOMAXCONN,
        backend: Backend | None = None,
        on_frame: FrameHandler | None = None,
        max_connections: int = 10_000,
    ) -> Reactor:
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise ValueError("listen supports IPv4 and IPv6")

        server = socket.socket(family, socket.SOCK_STREAM)
        try:
            server.setblocking(False)
            server.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_REUSEADDR,
                1,
            )
            server.bind((host, port))
            server.listen(backlog)

            return cls(
                server,
                backend=backend,
                on_frame=on_frame,
                max_connections=max_connections,
            )
        except BaseException:
            _close_socket(server)
            raise

    @property
    def listener(self) -> socket.socket:
        return self._server

    @property
    def state(self) -> ReactorState:
        return self._state

    @property
    def connection_count(self) -> int:
        return len(self._clients)

    def __enter__(self) -> Reactor:
        if self._state == ReactorState.CLOSED:
            raise RuntimeError("reactor is closed")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def _alive(self, client: _Client) -> bool:
        return self._clients.get(client.fd) is client

    def _close_client(self, client: _Client) -> None:
        if not self._alive(client):
            return

        del self._clients[client.fd]
        client.state = _ClientState.CLOSED

        try:
            self._backend.unregister(client.fd)
        finally:
            _close_socket(client.sock)

            while client.outbound:
                client.outbound.popleft().release()

            client.queued_bytes = 0

    def close_connection(self, fd: int) -> None:
        client = self._clients.get(fd)
        if client is not None:
            self._close_client(client)

    def _update_interest(self, client: _Client) -> None:
        if not self._alive(client):
            return

        mask = 0
        if (
            client.state == _ClientState.OPEN
            and not client.read_paused
        ):
            mask |= READ

        if client.outbound:
            mask |= WRITE

        if mask == 0:
            self._close_client(client)
        elif mask != client.mask:
            self._backend.modify(client.fd, mask, client)
            client.mask = mask

    def send_bytes(self, fd: int, data: bytes) -> bool:
        """Queue immutable output; False means it cannot be accepted."""
        if not isinstance(data, bytes):
            raise TypeError("queued output must be immutable bytes")

        client = self._clients.get(fd)
        if client is None or client.state != _ClientState.OPEN:
            return False

        if not data:
            return True

        if len(data) > OUTBOUND_HARD_LIMIT - client.queued_bytes:
            # The protocol permits dropping ERROR at the hard limit.
            _LOGGER.debug(
                "slow consumer fd=%d exceeded output limit",
                fd,
            )
            self._close_client(client)
            return False

        client.outbound.append(memoryview(data))
        client.queued_bytes += len(data)

        if client.queued_bytes >= OUTBOUND_SOFT_LIMIT:
            client.read_paused = True

        self._update_interest(client)
        return True

    def send_frame(self, fd: int, frame: Frame) -> bool:
        return self.send_bytes(fd, frame.to_bytes())

    def close_after_flush(self, fd: int) -> None:
        client = self._clients.get(fd)
        if client is not None:
            client.state = _ClientState.DRAINING
            self._update_interest(client)

    def _protocol_error(
        self,
        client: _Client,
        error: ProtocolError,
        *,
        request_id: int | None = None,
    ) -> None:
        if (
            not self._alive(client)
            or client.state != _ClientState.OPEN
        ):
            return

        message = error.code.name.encode("ascii")
        payload = _ERROR_PREFIX.pack(
            int(error.code),
            int(error.fatal),
            len(message),
        ) + message

        self.send_frame(
            client.fd,
            Frame(
                FrameType.ERROR,
                (
                    error.request_id
                    if request_id is None
                    else request_id
                ),
                payload,
            ),
        )

        if error.fatal:
            self.close_after_flush(client.fd)

    def _dispatch_frame(
        self,
        client: _Client,
        frame: Frame,
    ) -> None:
        try:
            if self._on_frame is None:
                self.send_frame(client.fd, frame)
            else:
                self._on_frame(self, client.fd, frame)
        except ProtocolError as error:
            self._protocol_error(
                client,
                error,
                request_id=frame.request_id,
            )
        except Exception:
            _LOGGER.exception(
                "frame handler failed for fd=%d",
                client.fd,
            )
            self._close_client(client)

    def _connection_error(
        self,
        client: _Client,
        error: OSError,
    ) -> None:
        if error.errno in _DISCONNECTED:
            _LOGGER.debug(
                "connection fd=%d disconnected: %s",
                client.fd,
                error,
            )
        else:
            _LOGGER.warning(
                "connection fd=%d failed: %s",
                client.fd,
                error,
            )

        self._close_client(client)

    def _read_client(self, client: _Client) -> None:
        remaining = READ_BUDGET

        for _ in range(IO_OPERATION_BUDGET):
            if (
                remaining == 0
                or not self._alive(client)
                or client.state != _ClientState.OPEN
                or client.read_paused
            ):
                return

            try:
                count = client.sock.recv_into(
                    self._scratch,
                    remaining,
                )
            except OSError as error:
                if error.errno == errno.EINTR:
                    continue
                if error.errno in _WOULD_BLOCK:
                    return

                self._connection_error(client, error)
                return

            if count == 0:
                # TCP half-close still allows previously queued replies.
                self.close_after_flush(client.fd)
                return

            remaining -= count
            failure: ProtocolError | None = None

            try:
                with self._read_view[:count] as buf:
                    frames = client.feed(buf)
            except ProtocolError as error:
                frames = error.completed_frames
                failure = error

            for frame in frames:
                if (
                    not self._alive(client)
                    or client.state != _ClientState.OPEN
                ):
                    return
                self._dispatch_frame(client, frame)

            if not self._alive(client):
                return

            for error in client.decoder.drain_errors():
                self._protocol_error(client, error)

            if failure is not None:
                self._protocol_error(client, failure)
                return

    def _write_client(self, client: _Client) -> None:
        remaining = WRITE_BUDGET

        for _ in range(IO_OPERATION_BUDGET):
            if remaining == 0 or not client.outbound:
                break

            head = client.outbound[0]
            try:
                with head[:min(len(head), remaining)] as buf:
                    count = client.sock.send(buf)
            except OSError as error:
                if error.errno == errno.EINTR:
                    continue
                if error.errno in _WOULD_BLOCK:
                    break

                self._connection_error(client, error)
                return

            if count == 0:
                self._close_client(client)
                return

            remaining -= count
            client.queued_bytes -= count

            if count == len(head):
                client.outbound.popleft().release()
            else:
                client.outbound[0] = head[count:]
                head.release()

        if (
            client.read_paused
            and client.queued_bytes <= OUTBOUND_LOW_LIMIT
        ):
            client.read_paused = False

        self._update_interest(client)

    def _accept_clients(self) -> None:
        # Attempts count too, so repeated EINTR cannot monopolize the loop.
        for _ in range(ACCEPT_BUDGET):
            try:
                sock, _address = self._server.accept()
            except OSError as error:
                if error.errno == errno.EINTR:
                    continue
                if error.errno in _WOULD_BLOCK:
                    return
                if error.errno in _TRANSIENT_ACCEPT_ERRORS:
                    continue

                if error.errno in _RESOURCE_ERRORS:
                    self._backend.unregister(self._server_fd)
                    self._accept_resume_at = (
                        time.monotonic() + _ACCEPT_RETRY_DELAY
                    )
                    _LOGGER.warning(
                        "temporarily pausing accept: %s",
                        error,
                    )
                    return

                raise

            try:
                sock.setblocking(False)

                if len(self._clients) >= self._max_connections:
                    _close_socket(sock)
                    continue

                client = _Client(sock, sock.fileno())
                self._backend.register(client.fd, READ, client)
                self._clients[client.fd] = client
            except OSError as error:
                _close_socket(sock)
                _LOGGER.debug(
                    "accepted socket setup failed: %s",
                    error,
                )
            except BaseException:
                _close_socket(sock)
                raise

    def _resume_accepting(self) -> None:
        if (
            self._accept_resume_at is not None
            and time.monotonic() >= self._accept_resume_at
        ):
            self._backend.register(
                self._server_fd,
                READ,
                self._listener_token,
            )
            self._accept_resume_at = None

    def _drain_wakeup(self) -> None:
        if self._wake_reader is None:
            return

        for _ in range(IO_OPERATION_BUDGET):
            try:
                count = self._wake_reader.recv_into(self._scratch)
            except OSError as error:
                if error.errno == errno.EINTR:
                    continue
                if error.errno in _WOULD_BLOCK:
                    return
                raise

            if count == 0:
                self._state = ReactorState.STOPPING
                return

    def run_once(self, timeout: float | None = None) -> int:
        if self._state == ReactorState.CLOSED:
            raise RuntimeError("reactor is closed")
        if self._state == ReactorState.STOPPING:
            return 0
        if self._in_poll:
            raise RuntimeError("reactor dispatch is not reentrant")

        self._in_poll = True
        try:
            self._resume_accepting()

            if self._accept_resume_at is not None:
                retry_in = max(
                    0.0,
                    self._accept_resume_at - time.monotonic(),
                )
                timeout = (
                    retry_in
                    if timeout is None
                    else min(timeout, retry_in)
                )

            events = self._backend.poll(timeout)
            dispatched = 0

            for event in events:
                if self._state in (
                    ReactorState.STOPPING,
                    ReactorState.CLOSED,
                ):
                    break

                if event.data is self._wakeup_token:
                    self._drain_wakeup()

                elif event.data is self._listener_token:
                    if event.mask & (ERROR | HANGUP):
                        raise OSError(
                            errno.EIO,
                            "listening socket failed",
                        )
                    if event.mask & READ:
                        self._accept_clients()

                elif isinstance(event.data, _Client):
                    client = event.data

                    # Cached events must not operate on a reused fd.
                    if not self._alive(client):
                        continue

                    if event.mask & (ERROR | HANGUP):
                        self._close_client(client)
                    else:
                        if event.mask & (READ | PEER_CLOSED):
                            self._read_client(client)

                        if (
                            self._alive(client)
                            and event.mask & WRITE
                        ):
                            self._write_client(client)

                dispatched += 1

            if self._state not in (
                ReactorState.STOPPING,
                ReactorState.CLOSED,
            ):
                self._resume_accepting()

            return dispatched

        finally:
            self._in_poll = False

    def run_forever(self) -> None:
        if (
            self._state != ReactorState.READY
            or self._in_poll
        ):
            raise RuntimeError("reactor is not ready to run")

        self._state = ReactorState.RUNNING
        try:
            while self._state == ReactorState.RUNNING:
                self.run_once()
        finally:
            self.close()

    def stop(self) -> None:
        """Request immediate M2 shutdown; durable draining belongs to M8."""
        if self._state in (
            ReactorState.STOPPING,
            ReactorState.CLOSED,
        ):
            return

        self._state = ReactorState.STOPPING

        if self._wake_writer is None:
            return

        while True:
            try:
                self._wake_writer.send(b"\x00")
                return
            except OSError as error:
                if error.errno == errno.EINTR:
                    continue
                if error.errno in _WOULD_BLOCK:
                    return

                _LOGGER.debug("wakeup write failed: %s", error)
                return

    def close(self) -> None:
        if self._state == ReactorState.CLOSED:
            return

        self._state = ReactorState.CLOSED

        try:
            # Closing the poller removes all interests before fds can be reused.
            self._backend.close()
        finally:
            try:
                for client in list(self._clients.values()):
                    self._close_client(client)
            finally:
                _close_socket(self._server)

                if self._wake_reader is not None:
                    _close_socket(self._wake_reader)
                if self._wake_writer is not None:
                    _close_socket(self._wake_writer)

                self._read_view.release()