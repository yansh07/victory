from __future__ import annotations

import errno
import queue
import select
import socket
import struct
import sys
import threading
import time
from collections.abc import Iterator
from concurrent.futures import Future
from dataclasses import dataclass
from enum import IntEnum
from typing import cast

import pytest

from victory.net.backends import Backend, Event, create_backend
from victory.net.reactor import Reactor, ReactorState, _Client
from victory.protocol.decoder import FrameDecoder
from victory.protocol.frame import Frame, FrameType

pytestmark = pytest.mark.skipif(
    not (
        sys.platform.startswith("linux")
        or sys.platform == "darwin"
    ),
    reason="the reactor targets Linux and macOS development environments",
)

_HEADER = struct.Struct("!HBBBBII")
_SEND_BUFFER = 1024
_TIMEOUT = 15.0
_WOULD_BLOCK = frozenset((errno.EAGAIN, errno.EWOULDBLOCK))


def _wait_socket(
    sock: socket.socket,
    *,
    write: bool,
    deadline: float,
) -> None:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("socket operation timed out")

        try:
            readable, writable, exceptional = select.select(
                [] if write else [sock],
                [sock] if write else [],
                [sock],
                remaining,
            )
        except InterruptedError:
            continue

        if exceptional:
            code = sock.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_ERROR,
            )
            raise OSError(
                code or errno.EIO,
                "socket reported an error",
            )

        if readable or writable:
            return


def _connect(address: tuple[str, int]) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.setblocking(False)
        sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_SNDBUF,
            _SEND_BUFFER,
        )

        code = sock.connect_ex(address)
        if code not in (0, errno.EISCONN):
            if code not in (
                errno.EINPROGRESS,
                errno.EALREADY,
                errno.EINTR,
                errno.EAGAIN,
                errno.EWOULDBLOCK,
            ):
                raise OSError(code, "connect_ex failed")

            _wait_socket(
                sock,
                write=True,
                deadline=time.monotonic() + _TIMEOUT,
            )
            code = sock.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_ERROR,
            )
            if code:
                raise OSError(code, "connection failed")

        return sock
    except BaseException:
        sock.close()
        raise


def _send_all(sock: socket.socket, data: bytes) -> None:
    deadline = time.monotonic() + _TIMEOUT
    offset = 0

    with memoryview(data) as view:
        while offset < len(view):
            if time.monotonic() >= deadline:
                raise TimeoutError("sending the packet timed out")

            try:
                with view[offset:] as buf:
                    count = sock.send(buf)
            except OSError as error:
                if error.errno == errno.EINTR:
                    continue
                if error.errno in _WOULD_BLOCK:
                    _wait_socket(
                        sock,
                        write=True,
                        deadline=deadline,
                    )
                    continue
                raise

            if count == 0:
                raise ConnectionError("socket closed while sending")

            offset += count


def _receive_exact(sock: socket.socket, size: int) -> bytes:
    deadline = time.monotonic() + _TIMEOUT
    result = bytearray(size)
    offset = 0

    with memoryview(result) as view:
        while offset < size:
            if time.monotonic() >= deadline:
                raise TimeoutError("receiving the echo timed out")

            try:
                with view[offset:] as buf:
                    count = sock.recv_into(buf)
            except OSError as error:
                if error.errno == errno.EINTR:
                    continue
                if error.errno in _WOULD_BLOCK:
                    _wait_socket(
                        sock,
                        write=False,
                        deadline=deadline,
                    )
                    continue
                raise

            if count == 0:
                raise EOFError(
                    f"echo ended after {offset} of {size} bytes"
                )

            offset += count

    return bytes(result)


class _MeasuredBackend:
    def __init__(self, backend: Backend) -> None:
        self.backend = backend
        self.registered: set[int] = set()
        self.poll_calls = 0
        self.poll_wall_seconds = 0.0

    def register(
        self,
        fd: int,
        mask: int,
        data: object = None,
    ) -> None:
        self.backend.register(fd, mask, data)
        self.registered.add(fd)

    def modify(
        self,
        fd: int,
        mask: int,
        data: object = None,
    ) -> None:
        self.backend.modify(fd, mask, data)

    def unregister(self, fd: int) -> None:
        self.backend.unregister(fd)
        self.registered.discard(fd)

    def poll(self, timeout: float | None = None) -> list[Event]:
        self.poll_calls += 1
        started = time.monotonic()
        try:
            return self.backend.poll(timeout)
        finally:
            self.poll_wall_seconds += time.monotonic() - started

    def close(self) -> None:
        self.backend.close()
        self.registered.clear()


class EchoHandler:
    def __init__(self) -> None:
        self.frames = 0

    def __call__(
        self,
        reactor: Reactor,
        fd: int,
        frame: Frame,
    ) -> None:
        # Reactor._read_client already feeds its per-connection decoder.
        # Refeeding wire bytes here would decode each connection twice.
        assert reactor.send_bytes(fd, frame.to_bytes())
        self.frames += 1


@dataclass(frozen=True, slots=True)
class _Snapshot:
    accepted: int
    closed: int
    active: int
    partial_buffers: int
    configured_send_buffers: int
    largest_accept_batch: int
    frames: int
    send_calls: int
    partial_sends: int
    bytes_sent: int
    queued_bytes: int
    registry_matches: bool
    poll_calls: int
    poll_wall_seconds: float
    thread_cpu_seconds: float


class _CommandKind(IntEnum):
    SNAPSHOT = 1
    STOP = 2


@dataclass(slots=True)
class _Command:
    kind: _CommandKind
    result: Future[_Snapshot | None]


class _ObservedReactor(Reactor):
    def __init__(
        self,
        listener: socket.socket,
        backend: _MeasuredBackend,
        handler: EchoHandler,
        commands: queue.Queue[_Command],
    ) -> None:
        self.measured_backend = backend
        self.handler = handler
        self.commands = commands
        self.accepted = 0
        self.closed = 0
        self.configured_send_buffers = 0
        self.largest_accept_batch = 0
        self.send_calls = 0
        self.partial_sends = 0
        self.bytes_sent = 0

        super().__init__(
            listener,
            backend=cast(Backend, backend),
            on_frame=handler,
            max_connections=256,
        )

    def _accept_clients(self) -> None:
        previous = set(self._clients)
        super()._accept_clients()
        accepted = set(self._clients) - previous

        self.largest_accept_batch = max(
            self.largest_accept_batch,
            len(accepted),
        )

        # No accepted descriptor can be read until this callback returns.
        for fd in accepted:
            client = self._clients[fd]
            assert not client.sock.getblocking()

            client.sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_SNDBUF,
                _SEND_BUFFER,
            )

            # Kernels may double or clamp the requested buffer size.
            assert client.sock.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_SNDBUF,
            ) >= _SEND_BUFFER

            self.configured_send_buffers += 1
            self.accepted += 1

    def _close_client(self, client: _Client) -> None:
        existed = self._alive(client)
        super()._close_client(client)
        if existed:
            self.closed += 1

    def _snapshot(self) -> _Snapshot:
        registered = self.measured_backend.registered.copy()
        registered.discard(self._server_fd)

        if self._wake_reader is not None:
            registered.discard(self._wake_reader.fileno())

        return _Snapshot(
            accepted=self.accepted,
            closed=self.closed,
            active=self.connection_count,
            partial_buffers=sum(
                client.decoder.buffered_bytes > 0
                for client in self._clients.values()
            ),
            configured_send_buffers=self.configured_send_buffers,
            largest_accept_batch=self.largest_accept_batch,
            frames=self.handler.frames,
            send_calls=self.send_calls,
            partial_sends=self.partial_sends,
            bytes_sent=self.bytes_sent,
            queued_bytes=sum(
                client.queued_bytes
                for client in self._clients.values()
            ),
            registry_matches=registered == set(self._clients),
            poll_calls=self.measured_backend.poll_calls,
            poll_wall_seconds=(
                self.measured_backend.poll_wall_seconds
            ),
            thread_cpu_seconds=time.thread_time(),
        )

    def _drain_wakeup(self) -> None:
        super()._drain_wakeup()

        while True:
            try:
                command = self.commands.get_nowait()
            except queue.Empty:
                return

            try:
                if command.kind == _CommandKind.SNAPSHOT:
                    command.result.set_result(self._snapshot())
                else:
                    self.stop()
                    command.result.set_result(None)
            except BaseException as error:
                command.result.set_exception(error)
                raise


class _RunningServer:
    def __init__(self, reactor: _ObservedReactor) -> None:
        self.reactor = reactor
        host, port = reactor.listener.getsockname()
        self.address: tuple[str, int] = (host, port)

        self.started = threading.Event()
        self.failures: queue.Queue[BaseException] = queue.Queue()
        self.owner_ident: int | None = None
        self.thread = threading.Thread(
            target=self._run,
            name="victory-reactor-integration",
            daemon=True,
        )

    def _run(self) -> None:
        self.owner_ident = threading.get_ident()
        self.started.set()

        try:
            self.reactor.run_forever()
        except BaseException as error:
            self.failures.put(error)
        finally:
            while True:
                try:
                    command = self.reactor.commands.get_nowait()
                except queue.Empty:
                    break

                if not command.result.done():
                    command.result.set_exception(
                        RuntimeError(
                            "reactor stopped before processing command"
                        )
                    )

    def start(self) -> None:
        self.thread.start()
        assert self.started.wait(_TIMEOUT), (
            "reactor thread did not start"
        )

    def _request(self, kind: _CommandKind) -> _Snapshot | None:
        assert self.thread.is_alive(), (
            "reactor thread exited unexpectedly"
        )

        result: Future[_Snapshot | None] = Future()
        self.reactor.commands.put(_Command(kind, result))

        writer = self.reactor._wake_writer
        assert writer is not None
        _send_all(writer, b"\x00")

        return result.result(timeout=_TIMEOUT)

    def snapshot(self) -> _Snapshot:
        result = self._request(_CommandKind.SNAPSHOT)
        assert isinstance(result, _Snapshot)
        return result

    def stop(self) -> None:
        try:
            if self.thread.is_alive():
                self._request(_CommandKind.STOP)
        finally:
            self.thread.join(timeout=_TIMEOUT)

        assert not self.thread.is_alive(), (
            "reactor thread failed to stop"
        )
        assert self.reactor.state == ReactorState.CLOSED
        assert self.reactor.connection_count == 0
        assert self.reactor.listener.fileno() == -1
        assert not self.reactor.measured_backend.registered

        if not self.failures.empty():
            error = self.failures.get_nowait()
            raise AssertionError(
                "reactor loop raised an exception"
            ) from error


@pytest.fixture(params=("default", "selector"))
def echo_server(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_RunningServer]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setblocking(False)

    try:
        listener.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_SNDBUF,
            _SEND_BUFFER,
        )
        listener.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1,
        )
        listener.bind(("127.0.0.1", 0))
        listener.listen(256)

        backend = _MeasuredBackend(
            create_backend(
                development=request.param == "selector"
            )
        )
        reactor = _ObservedReactor(
            listener,
            backend,
            EchoHandler(),
            queue.Queue(),
        )
    except BaseException:
        listener.close()
        raise

    running = _RunningServer(reactor)
    original_send = socket.socket.send

    def measured_send(
        sock: socket.socket,
        data: bytes | bytearray | memoryview,
        flags: int = 0,
    ) -> int:
        server_write = (
            threading.get_ident() == running.owner_ident
            and sock.fileno() in reactor._clients
        )
        if not server_write:
            return original_send(sock, data, flags)

        # Bound real writes so fast loopback cannot bypass short-send logic.
        # Counts always reflect bytes actually accepted by the kernel.
        with memoryview(data) as view:
            with view[:_SEND_BUFFER] as buf:
                count = original_send(sock, buf, flags)

        reactor.send_calls += 1
        reactor.bytes_sent += count
        if 0 < count < len(data):
            reactor.partial_sends += 1

        return count

    monkeypatch.setattr(socket.socket, "send", measured_send)

    try:
        running.start()
        assert running.snapshot().registry_matches
        yield running
    finally:
        if running.thread.ident is not None:
            running.stop()
        else:
            reactor.close()


def _wait_for_cleanup(server: _RunningServer) -> _Snapshot:
    deadline = time.monotonic() + _TIMEOUT

    while True:
        snapshot = server.snapshot()
        if snapshot.active == 0:
            assert snapshot.registry_matches
            return snapshot

        if time.monotonic() >= deadline:
            raise AssertionError(
                f"connections were not cleaned up: {snapshot}"
            )

        threading.Event().wait(0.01)


def test_partial_write_execution(
    echo_server: _RunningServer,
) -> None:
    # STATS_OK permits a full frame payload without an inner u16 prefix.
    payload = b"data=" + b"x" * (65_536 - 6) + b"\n"
    packet = _HEADER.pack(
        0xCE57,
        1,
        int(FrameType.STATS_OK),
        0,
        0,
        0x10203040,
        len(payload),
    ) + payload

    assert len(payload) == 65_536
    assert len(packet) == 65_550

    sock = _connect(echo_server.address)
    try:
        _send_all(sock, packet)
        echoed = _receive_exact(sock, len(packet))

        assert echoed == packet

        decoder = FrameDecoder()
        assert decoder.feed(echoed) == [
            Frame(
                FrameType.STATS_OK,
                0x10203040,
                payload,
            )
        ]
        assert decoder.buffered_bytes == 0
        assert decoder.errors == []

        snapshot = echo_server.snapshot()
        assert snapshot.registry_matches
        assert snapshot.accepted == 1
        assert snapshot.configured_send_buffers == 1
        assert snapshot.frames == 1
        assert snapshot.bytes_sent == len(packet)
        assert snapshot.queued_bytes == 0
        assert snapshot.send_calls >= 2
        assert snapshot.partial_sends > 0
    finally:
        sock.close()

    snapshot = _wait_for_cleanup(echo_server)
    assert snapshot.closed == 1


def test_accept_loop_under_load(
    echo_server: _RunningServer,
) -> None:
    worker_count = 100
    barrier = threading.Barrier(worker_count + 1)
    release = threading.Event()
    ready: queue.Queue[int] = queue.Queue()
    failures: queue.Queue[tuple[int, BaseException]] = queue.Queue()

    incomplete_packet = _HEADER.pack(
        0xCE57,
        1,
        int(FrameType.STATS_OK),
        0,
        0,
        1,
        65_536,
    ) + b"partial-payload"

    def worker(index: int) -> None:
        sock: socket.socket | None = None

        try:
            barrier.wait(timeout=_TIMEOUT)
            sock = _connect(echo_server.address)
            _send_all(sock, incomplete_packet)
            ready.put(index)

            if not release.wait(_TIMEOUT):
                raise TimeoutError(
                    "worker disconnect release timed out"
                )

            if index % 2 == 0:
                # SO_LINGER is a native kernel structure, not a wire schema.
                sock.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_LINGER,
                    struct.pack("@ii", 1, 0),
                )
        except BaseException as error:
            failures.put((index, error))
        finally:
            if sock is not None:
                sock.close()

    workers = [
        threading.Thread(
            target=worker,
            args=(index,),
            name=f"victory-client-{index}",
            daemon=True,
        )
        for index in range(worker_count)
    ]

    try:
        for thread in workers:
            thread.start()

        barrier.wait(timeout=_TIMEOUT)
        deadline = time.monotonic() + _TIMEOUT
        connected: set[int] = set()

        while len(connected) < worker_count:
            if not failures.empty():
                index, error = failures.get_nowait()
                raise AssertionError(
                    f"worker {index} failed"
                ) from error

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError(
                    "not all 100 workers connected"
                )

            try:
                connected.add(
                    ready.get(timeout=min(0.1, remaining))
                )
            except queue.Empty:
                continue

        while True:
            snapshot = echo_server.snapshot()
            assert snapshot.registry_matches

            if (
                snapshot.active == worker_count
                and snapshot.partial_buffers == worker_count
            ):
                break

            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"incomplete registration or reads: {snapshot}"
                )

            threading.Event().wait(0.01)

        assert snapshot.accepted == worker_count
        assert snapshot.configured_send_buffers == worker_count
        assert snapshot.closed == 0
        assert snapshot.frames == 0
        assert snapshot.queued_bytes == 0
        assert 1 <= snapshot.largest_accept_batch <= 64

    finally:
        release.set()
        barrier.abort()

        join_deadline = time.monotonic() + _TIMEOUT
        for thread in workers:
            if thread.ident is not None:
                thread.join(
                    timeout=max(
                        0.0,
                        join_deadline - time.monotonic(),
                    )
                )

    assert not [
        thread.name
        for thread in workers
        if thread.is_alive()
    ]

    if not failures.empty():
        index, error = failures.get_nowait()
        raise AssertionError(
            f"worker {index} failed"
        ) from error

    snapshot = _wait_for_cleanup(echo_server)
    assert snapshot.accepted == worker_count
    assert snapshot.closed == worker_count
    assert snapshot.frames == 0
    assert snapshot.queued_bytes == 0


def test_idle_cpu_blocks_in_kernel_poll(
    echo_server: _RunningServer,
) -> None:
    before = echo_server.snapshot()
    assert before.active == 0
    assert before.queued_bytes == 0

    started = time.monotonic()
    threading.Event().wait(0.35)
    elapsed = time.monotonic() - started

    after = echo_server.snapshot()

    cpu_seconds = (
        after.thread_cpu_seconds
        - before.thread_cpu_seconds
    )
    poll_calls = after.poll_calls - before.poll_calls
    poll_seconds = (
        after.poll_wall_seconds
        - before.poll_wall_seconds
    )

    assert elapsed >= 0.30
    assert 1 <= poll_calls <= 4
    assert poll_seconds >= elapsed * 0.8
    assert cpu_seconds < elapsed * 0.2
    assert after.active == 0
    assert after.registry_matches