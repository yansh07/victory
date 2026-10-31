from __future__ import annotations

import errno
import json
import os
import queue
import select
import selectors
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
import zlib
from collections import deque
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from typing import Any

import pytest

from victory.core.router import (
    AppendWalAction,
    CloseSessionAction,
    EnqueueClientBufferAction,
    Router,
)
from victory.lifecycle.shutdown import (
    DrainConnection,
    ShutdownCoordinator,
    ShutdownState,
)
from victory.net.reactor import Reactor
from victory.protocol.decoder import FrameDecoder
from victory.storage import wal as wal_module
from victory.storage.wal import (
    MAX_RECORD_PAYLOAD,
    SEGMENT_HEADER,
    SEGMENT_MAGIC,
    SEGMENT_VERSION,
    RecordType,
    WalRecord,
    WriteAheadLog,
    decode_message,
)
from victory.storage.writer_thread import WalWriter

pytestmark = pytest.mark.skipif(
    os.name != "posix",
    reason="requires POSIX signal and WAL semantics",
)

CLIENT_COUNT = 5
MESSAGES_PER_CLIENT = 80
WARMUP_PER_CLIENT = 4
BODY_SIZE = 2048
SHUTDOWN_MS = 5000
TEST_TIMEOUT = 25.0

NODE_ID = 17
TOKEN = "shutdown-integration-token"
ROOM = "general"

HEADER = struct.Struct("!HBBBBII")
ACK = struct.Struct("!BBQ")
RECORD_HEADER = struct.Struct("!IIQB")


def _string(value: str) -> bytes:
    data = value.encode("utf-8")
    return struct.pack("!H", len(data)) + data


def _packet(
    frame_type: int,
    request_id: int,
    payload: bytes,
) -> bytes:
    return HEADER.pack(
        0xCE57,
        1,
        frame_type,
        0,
        0,
        request_id,
        len(payload),
    ) + payload


def _body(client_index: int, message_id: int) -> bytes:
    pattern = (
        struct.pack("!II", client_index, message_id)
        + b"\x00\xffvictory"
    )
    repetitions = (BODY_SIZE + len(pattern) - 1) // len(pattern)
    return (pattern * repetitions)[:BODY_SIZE]


def _message_packet(
    client_index: int,
    message_id: int,
) -> bytes:
    body = _body(client_index, message_id)
    payload = (
        _string(ROOM)
        + struct.pack("!QH", message_id, len(body))
        + body
    )
    return _packet(0x04, 1000 + message_id, payload)


def _report(event: str, **fields: Any) -> None:
    data = (
        json.dumps({"event": event, **fields}) + "\n"
    ).encode("utf-8")
    assert len(data) <= 4096

    while True:
        try:
            assert os.write(sys.stdout.fileno(), data) == len(data)
            return
        except InterruptedError:
            continue


class _BackendBridge:
    """Dispatch auxiliary readiness through the real Reactor backend."""

    def __init__(self, backend: Any, server: _Server) -> None:
        self.backend = backend
        self.server = server

    def register(
        self,
        fd: int,
        mask: int,
        data: object = None,
    ) -> None:
        self.backend.register(fd, mask, data)

    def modify(
        self,
        fd: int,
        mask: int,
        data: object = None,
    ) -> None:
        self.backend.modify(fd, mask, data)

    def unregister(self, fd: int) -> None:
        self.backend.unregister(fd)

    def poll(self, timeout: float | None) -> list[Any]:
        events = self.backend.poll(timeout)
        self.server.synchronize_connections()
        ordinary: list[Any] = []

        for event in events:
            coordinator = self.server.coordinator

            if event.fd == self.server.gate_reader:
                self.server.drain_gate_notification()
            elif (
                event.data is coordinator
                or event.data is self.server.writer
            ):
                coordinator.handle_event(event)
            elif event.fd == self.server.listener_fd:
                # A poll batch can contain listener readiness captured before
                # the coordinator closed the listener.
                if coordinator.state == ShutdownState.RUNNING:
                    ordinary.append(event)
            else:
                ordinary.append(event)

        if self.server.coordinator.finished:
            return []

        return ordinary

    def close(self) -> None:
        self.backend.close()


class _Server:
    def __init__(self, directory: Path, mode: str) -> None:
        self.mode = mode
        self.directory = directory
        self.router = Router(NODE_ID, tokens=(TOKEN,))

        self.bindings: dict[int, DrainConnection] = {}
        self.fd_to_session: dict[int, int] = {}
        self.session_to_fd: dict[int, int] = {}
        self.client_records: dict[int, Any] = {}
        self.backlog: deque[AppendWalAction] = deque()

        self.received_messages = 0
        self.ready_reported = False
        self.draining_reported = False
        self.exit_status: int | None = None

        self.fsync_held = threading.Event()
        self.fsync_release = threading.Event()
        self.original_fsync = wal_module._fsync

        self.gate_reader, self.gate_writer = os.pipe()
        for fd in (self.gate_reader, self.gate_writer):
            os.set_blocking(fd, False)
            os.set_inheritable(fd, False)

        listener = socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM,
        )
        listener.setblocking(False)
        listener.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1,
        )
        listener.bind(("127.0.0.1", 0))
        listener.listen(128)

        self.listener = listener
        self.listener_fd = listener.fileno()
        self.address = listener.getsockname()

        self.reactor = Reactor(
            listener,
            on_frame=self.on_frame,
        )
        self.backend = _BackendBridge(
            self.reactor._backend,
            self,
        )
        self.reactor._backend = self.backend
        self.backend.register(self.gate_reader, 1, self)

        self.log = WriteAheadLog(directory)
        wal_module._fsync = self.controlled_fsync

        self.writer = WalWriter(
            self.log,
            self.backend,
            max_batch_records=8,
            max_batch_bytes=128 * 1024,
        )
        self.writer.start()

        self.coordinator = ShutdownCoordinator(
            self.backend,
            self.writer,
            self.router,
            self.bindings,
            [listener],
            apply_actions=self.apply_actions,
            flush_pending_wal=self.admit_backlog,
            on_exit=self.on_exit,
            timeout_ms=SHUTDOWN_MS,
        )

    def controlled_fsync(self, fd: int) -> None:
        if (
            fd == self.log._fd
            and (
                self.log.last_lsn
                >= CLIENT_COUNT * WARMUP_PER_CLIENT
            )
            and not self.fsync_held.is_set()
        ):
            self.fsync_held.set()

            # This test notification is separate from the durability ring:
            # no completion is published while fsync remains blocked.
            while True:
                try:
                    os.write(self.gate_writer, b"\x00")
                    break
                except InterruptedError:
                    continue
                except BlockingIOError:
                    break

            if not self.fsync_release.wait(TEST_TIMEOUT):
                raise TimeoutError(
                    "test fsync barrier was not released"
                )

        self.original_fsync(fd)

    def drain_gate_notification(self) -> None:
        while True:
            try:
                if not os.read(self.gate_reader, 4096):
                    return
            except InterruptedError:
                continue
            except BlockingIOError:
                return

    def ensure_connection(self, fd: int) -> int:
        client = self.reactor._clients[fd]

        if fd in self.fd_to_session:
            session_id = self.fd_to_session[fd]
            if self.client_records[session_id] is client:
                return session_id
            self.forget_session(session_id)

        session_id = self.router.open_session().session_id
        self.fd_to_session[fd] = session_id
        self.session_to_fd[session_id] = fd
        self.client_records[session_id] = client

        assert not client.sock.getblocking()
        client.sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_SNDBUF,
            65536,
        )

        self.bindings[session_id] = DrainConnection(
            session_id=session_id,
            fileno=client.sock.fileno,
            pending_bytes=(
                lambda client=client: client.queued_bytes
            ),
            enqueue=(
                lambda data, fd=fd:
                self.reactor.send_bytes(fd, data)
            ),
            close=(
                lambda session_id=session_id:
                self.close_session(session_id)
            ),
        )
        return session_id

    def forget_session(self, session_id: int) -> None:
        fd = self.session_to_fd.pop(session_id, None)

        if (
            fd is not None
            and self.fd_to_session.get(fd) == session_id
        ):
            del self.fd_to_session[fd]

        self.bindings.pop(session_id, None)
        self.client_records.pop(session_id, None)
        self.router.disconnect(session_id)

    def close_session(self, session_id: int) -> None:
        fd = self.session_to_fd.get(session_id)
        client = self.client_records.get(session_id)

        if (
            fd is not None
            and self.reactor._clients.get(fd) is client
        ):
            self.reactor.close_connection(fd)

        self.forget_session(session_id)

    def synchronize_connections(self) -> None:
        for session_id, fd in list(
            self.session_to_fd.items()
        ):
            if (
                self.reactor._clients.get(fd)
                is not self.client_records[session_id]
            ):
                self.forget_session(session_id)

        for fd in list(self.reactor._clients):
            self.ensure_connection(fd)

    def admit_backlog(self) -> None:
        while self.backlog:
            if not self.writer.submit(self.backlog[0]):
                return
            self.backlog.popleft()

    def apply_actions(self, actions: list[Any]) -> None:
        for action in actions:
            if isinstance(action, AppendWalAction):
                self.backlog.append(action)

            elif isinstance(action, EnqueueClientBufferAction):
                fd = self.session_to_fd.get(action.session_id)

                if (
                    fd is not None
                    and fd in self.reactor._clients
                ):
                    self.reactor.send_bytes(fd, action.packet)

            elif isinstance(action, CloseSessionAction):
                fd = self.session_to_fd.get(action.session_id)

                if (
                    fd is not None
                    and fd in self.reactor._clients
                ):
                    if action.after_flush:
                        self.reactor.close_after_flush(fd)
                    else:
                        self.close_session(action.session_id)

            else:
                raise TypeError(
                    "unexpected router action: "
                    f"{type(action).__name__}"
                )

        if self.backlog:
            self.admit_backlog()

    def on_frame(
        self,
        reactor: Reactor,
        fd: int,
        frame: Any,
    ) -> None:
        try:
            session_id = self.ensure_connection(fd)
            self.coordinator.dispatch_command(
                session_id,
                int(frame.type),
                frame.request_id,
                lambda: self.router.route(session_id, frame),
            )

            if int(frame.type) == 0x04:
                self.received_messages += 1
        except Exception:
            _report(
                "fatal",
                detail=traceback.format_exc()[-2000:],
            )
            raise

    def on_exit(self, status: int) -> None:
        self.exit_status = status
        deadline = self.coordinator.deadline

        started = (
            deadline - SHUTDOWN_MS / 1000.0
            if deadline is not None
            else time.monotonic()
        )

        _report(
            "finished",
            status=status,
            elapsed=time.monotonic() - started,
            pending_wal=self.writer.pending_count,
            pending_router=self.router.pending_count,
            connections=len(self.reactor._clients),
        )
        self.reactor.stop()

    def after_pass(self) -> None:
        self.synchronize_connections()
        self.coordinator.tick()

        if (
            not self.ready_reported
            and (
                self.received_messages
                == CLIENT_COUNT * MESSAGES_PER_CLIENT
            )
            and self.fsync_held.is_set()
        ):
            self.ready_reported = True
            _report(
                "load_ready",
                received=self.received_messages,
                connections=len(self.bindings),
                pending_wal=self.writer.pending_count,
                fsync_blocked=not self.fsync_release.is_set(),
            )

        if (
            not self.draining_reported
            and (
                self.coordinator.state
                != ShutdownState.RUNNING
            )
        ):
            self.draining_reported = True
            _report(
                "draining",
                signal_count=self.coordinator.signal_count,
                listener_closed=self.listener.fileno() == -1,
                pending_wal=self.writer.pending_count,
                fsync_blocked=not self.fsync_release.is_set(),
            )

            if self.mode == "graceful":
                self.fsync_release.set()

    def run(self) -> int:
        _report(
            "ready",
            host=self.address[0],
            port=self.address[1],
        )

        while not self.coordinator.finished:
            timeout = self.coordinator.get_next_timeout()
            self.reactor.run_once(timeout=timeout)
            self.after_pass()

        assert self.exit_status is not None
        return self.exit_status

    def close(self) -> None:
        self.fsync_release.set()
        self.coordinator.close()

        assert self.writer.close(
            TEST_TIMEOUT
        ), "WAL worker failed to stop"

        self.writer.drain_completions()
        self.backend.unregister(self.gate_reader)
        self.reactor.close()

        os.close(self.gate_reader)
        os.close(self.gate_writer)
        wal_module._fsync = self.original_fsync


class _ClientPhase(IntEnum):
    HELLO = 0
    JOIN = 1
    WAIT_WARMUP = 2
    WARMUP = 3
    WAIT_HEAVY = 4
    HEAVY = 5
    DRAINING = 6
    CLOSED = 7


@dataclass(slots=True)
class _ClientResult:
    index: int
    ready: threading.Event = field(
        default_factory=threading.Event
    )
    warm: threading.Event = field(
        default_factory=threading.Event
    )
    all_sent: threading.Event = field(
        default_factory=threading.Event
    )
    shutdown_seen: bool = False
    acknowledgments: dict[int, int] = field(
        default_factory=dict
    )
    delivered_sequences: set[int] = field(
        default_factory=set
    )


def _connect(
    address: tuple[str, int],
    timeout: float,
) -> socket.socket:
    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM,
    )
    sock.setblocking(False)

    try:
        error = sock.connect_ex(address)

        if error not in (
            0,
            errno.EINPROGRESS,
            errno.EWOULDBLOCK,
            errno.EALREADY,
            errno.EINTR,
        ):
            raise OSError(error, os.strerror(error))

        if error:
            deadline = time.monotonic() + timeout

            while True:
                remaining = deadline - time.monotonic()
                assert remaining > 0, "TCP connection timed out"

                try:
                    _, writable, exceptional = select.select(
                        [],
                        [sock],
                        [sock],
                        remaining,
                    )
                except InterruptedError:
                    continue

                if writable or exceptional:
                    error = sock.getsockopt(
                        socket.SOL_SOCKET,
                        socket.SO_ERROR,
                    )
                    if error:
                        raise OSError(
                            error,
                            os.strerror(error),
                        )
                    break

        return sock
    except BaseException:
        sock.close()
        raise


def _client_worker(
    address: tuple[str, int],
    result: _ClientResult,
    start_warmup: threading.Event,
    start_heavy: threading.Event,
    stop: threading.Event,
    panic_expected: threading.Event,
    errors: queue.Queue[str],
) -> None:
    sock: socket.socket | None = None

    try:
        sock = _connect(address, TEST_TIMEOUT)
        decoder = FrameDecoder()
        user = f"client_{result.index}"

        hello = (
            struct.pack("!I", 10000)
            + _string(user)
            + _string(TOKEN)
        )
        outgoing: deque[memoryview] = deque(
            [memoryview(_packet(0x01, 1, hello))]
        )

        phase = _ClientPhase.HELLO
        deadline = time.monotonic() + TEST_TIMEOUT

        while not stop.is_set():
            assert time.monotonic() < deadline, (
                f"client {user} timed out"
            )

            if (
                phase == _ClientPhase.WAIT_WARMUP
                and start_warmup.is_set()
            ):
                outgoing.extend(
                    memoryview(
                        _message_packet(
                            result.index,
                            message_id,
                        )
                    )
                    for message_id in range(
                        1,
                        WARMUP_PER_CLIENT + 1,
                    )
                )
                phase = _ClientPhase.WARMUP

            if (
                phase == _ClientPhase.WARMUP
                and (
                    len(result.acknowledgments)
                    == WARMUP_PER_CLIENT
                )
            ):
                result.warm.set()
                phase = _ClientPhase.WAIT_HEAVY

            if (
                phase == _ClientPhase.WAIT_HEAVY
                and start_heavy.is_set()
            ):
                outgoing.extend(
                    memoryview(
                        _message_packet(
                            result.index,
                            message_id,
                        )
                    )
                    for message_id in range(
                        WARMUP_PER_CLIENT + 1,
                        MESSAGES_PER_CLIENT + 1,
                    )
                )
                phase = _ClientPhase.HEAVY

            if (
                phase == _ClientPhase.HEAVY
                and not outgoing
            ):
                result.all_sent.set()

            try:
                readable, writable, exceptional = select.select(
                    [sock],
                    [sock] if outgoing else [],
                    [sock],
                    0.05,
                )
            except InterruptedError:
                continue

            assert not exceptional, (
                f"exceptional client socket: {user}"
            )

            if writable:
                try:
                    written = sock.send(outgoing[0])
                except (BlockingIOError, InterruptedError):
                    written = None

                if written is not None:
                    assert written > 0

                    if written == len(outgoing[0]):
                        outgoing.popleft()
                    else:
                        outgoing[0] = outgoing[0][written:]

            if not readable:
                continue

            try:
                data = sock.recv(64 * 1024)
            except (BlockingIOError, InterruptedError):
                continue

            if not data:
                phase = _ClientPhase.CLOSED
                break

            for frame in decoder.feed(data):
                frame_type = int(frame.type)

                if frame_type == 0x0B:
                    assert phase == _ClientPhase.HELLO
                    assert frame.request_id == 1

                    (
                        session_id,
                        node_id,
                        heartbeat,
                        maximum,
                    ) = struct.unpack("!QIII", frame.payload)

                    assert session_id > 0
                    assert node_id == NODE_ID
                    assert heartbeat >= 1000
                    assert maximum == 65536

                    outgoing.append(
                        memoryview(
                            _packet(
                                0x02,
                                2,
                                _string(ROOM),
                            )
                        )
                    )
                    phase = _ClientPhase.JOIN

                elif frame_type == 0x07:
                    acked_type, durable, seq = ACK.unpack(
                        frame.payload
                    )

                    if acked_type == 0x02:
                        assert phase == _ClientPhase.JOIN
                        assert (
                            frame.request_id,
                            durable,
                            seq,
                        ) == (2, 0, 0)

                        result.ready.set()
                        phase = _ClientPhase.WAIT_WARMUP
                    else:
                        assert acked_type == 0x04
                        assert durable == 1
                        assert seq > 0

                        message_id = frame.request_id - 1000

                        assert (
                            1 <= message_id
                            <= MESSAGES_PER_CLIENT
                        )
                        assert (
                            message_id
                            not in result.acknowledgments
                        )
                        result.acknowledgments[message_id] = seq

                elif frame_type == 0x09:
                    assert not result.shutdown_seen
                    assert frame.request_id == 0

                    reason, shutdown_ms = struct.unpack(
                        "!BI",
                        frame.payload,
                    )
                    assert reason == 0
                    assert shutdown_ms == SHUTDOWN_MS
                    assert not outgoing

                    result.shutdown_seen = True
                    phase = _ClientPhase.DRAINING

                elif frame_type == 0x0A:
                    assert frame.request_id == 0

                    room_size = struct.unpack_from(
                        "!H",
                        frame.payload,
                    )[0]
                    assert (
                        frame.payload[2:2 + room_size]
                        == ROOM.encode("ascii")
                    )

                    origin_node, seq = struct.unpack_from(
                        "!IQ",
                        frame.payload,
                        2 + room_size,
                    )
                    assert origin_node == NODE_ID
                    assert seq == (
                        len(result.delivered_sequences) + 1
                    )
                    result.delivered_sequences.add(seq)

                elif frame_type == 0x08:
                    code, fatal = struct.unpack_from(
                        "!HB",
                        frame.payload,
                    )
                    assert (code, fatal) == (17, 0), (
                        frame.payload
                    )

                else:
                    raise AssertionError(
                        "unexpected server frame type "
                        f"{frame_type}"
                    )

        if (
            not stop.is_set()
            and not panic_expected.is_set()
        ):
            assert phase == _ClientPhase.CLOSED
            assert result.shutdown_seen
            assert (
                len(result.acknowledgments)
                == MESSAGES_PER_CLIENT
            )

    except OSError as exc:
        if not (
            panic_expected.is_set()
            or stop.is_set()
        ):
            errors.put(
                f"client {result.index}: {exc!r}"
            )

    except Exception:
        errors.put(
            f"client {result.index}: "
            f"{traceback.format_exc()}"
        )

    finally:
        if sock is not None:
            sock.close()


class _ProcessReports:
    def __init__(
        self,
        process: subprocess.Popen[bytes],
    ) -> None:
        assert process.stdout is not None

        self.process = process
        self.fd = process.stdout.fileno()
        os.set_blocking(self.fd, False)

        self.selector = selectors.DefaultSelector()
        self.selector.register(
            self.fd,
            selectors.EVENT_READ,
        )
        self.buffer = bytearray()
        self.events: list[dict[str, Any]] = []

    def wait(
        self,
        event_name: str,
        timeout: float = TEST_TIMEOUT,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout

        while True:
            for event in self.events:
                if event["event"] == "fatal":
                    pytest.fail(event["detail"])

                if event["event"] == event_name:
                    return event

            remaining = deadline - time.monotonic()
            assert remaining > 0, (
                f"missing {event_name!r}: {self.events!r}"
            )

            for key, mask in self.selector.select(remaining):
                try:
                    data = os.read(key.fd, 65536)
                except (BlockingIOError, InterruptedError):
                    continue

                assert data, (
                    f"server exited before {event_name!r}; "
                    f"status={self.process.poll()}, "
                    f"output={bytes(self.buffer)!r}"
                )

                self.buffer.extend(data)

                while b"\n" in self.buffer:
                    line, _, remainder = self.buffer.partition(
                        b"\n"
                    )
                    self.buffer = bytearray(remainder)

                    try:
                        self.events.append(json.loads(line))
                    except (ValueError, TypeError):
                        pytest.fail(
                            "unexpected child output: "
                            + line.decode("utf-8", "replace")
                        )

    def close(self) -> None:
        self.selector.close()


class _RunningSystem:
    def __init__(
        self,
        directory: Path,
        mode: str,
    ) -> None:
        self.directory = directory
        self.mode = mode

        environment = os.environ.copy()
        source_root = str(
            Path(wal_module.__file__).resolve().parents[2]
        )
        existing = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = source_root + (
            os.pathsep + existing if existing else ""
        )

        # A subprocess keeps real signal handlers on the server's main thread.
        self.process = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve()),
                "--shutdown-server",
                str(directory),
                mode,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=environment,
        )

        self.reports = _ProcessReports(self.process)
        self.results = [
            _ClientResult(index)
            for index in range(CLIENT_COUNT)
        ]
        self.start_warmup = threading.Event()
        self.start_heavy = threading.Event()
        self.stop = threading.Event()
        self.panic_expected = threading.Event()
        self.errors: queue.Queue[str] = queue.Queue()
        self.threads: list[threading.Thread] = []

    def check_errors(self) -> None:
        messages: list[str] = []

        while True:
            try:
                messages.append(self.errors.get_nowait())
            except queue.Empty:
                break

        assert not messages, "\n".join(messages)

    def wait_flags(self, name: str) -> None:
        deadline = time.monotonic() + TEST_TIMEOUT

        for result in self.results:
            event = getattr(result, name)

            while not event.wait(0.05):
                self.check_errors()

                assert self.process.poll() is None, (
                    "server exited unexpectedly"
                )
                assert time.monotonic() < deadline, (
                    f"client flag {name!r} timed out"
                )

        self.check_errors()

    def start_load(self) -> tuple[str, int]:
        ready = self.reports.wait("ready")
        address = (ready["host"], ready["port"])

        for result in self.results:
            thread = threading.Thread(
                target=_client_worker,
                args=(
                    address,
                    result,
                    self.start_warmup,
                    self.start_heavy,
                    self.stop,
                    self.panic_expected,
                    self.errors,
                ),
                name=f"shutdown-client-{result.index}",
            )
            self.threads.append(thread)
            thread.start()

        self.wait_flags("ready")
        self.start_warmup.set()
        self.wait_flags("warm")
        self.start_heavy.set()

        loaded = self.reports.wait("load_ready")
        self.wait_flags("all_sent")

        assert loaded["connections"] == CLIENT_COUNT
        assert loaded["received"] == (
            CLIENT_COUNT * MESSAGES_PER_CLIENT
        )
        assert loaded["pending_wal"] > 0
        assert loaded["fsync_blocked"]

        return address

    def join_clients(self) -> None:
        deadline = time.monotonic() + TEST_TIMEOUT

        for thread in self.threads:
            thread.join(
                max(0.0, deadline - time.monotonic())
            )
            assert not thread.is_alive(), (
                f"client thread did not finish: {thread.name}"
            )

        self.check_errors()

    def close(self) -> None:
        self.stop.set()
        self.start_warmup.set()
        self.start_heavy.set()

        if self.process.poll() is None:
            self.process.kill()

        self.process.wait(TEST_TIMEOUT)

        deadline = time.monotonic() + TEST_TIMEOUT
        leaked: list[str] = []

        for thread in self.threads:
            thread.join(
                max(0.0, deadline - time.monotonic())
            )
            if thread.is_alive():
                leaked.append(thread.name)

        self.reports.close()

        assert self.process.stdout is not None
        self.process.stdout.close()

        assert not leaked, (
            f"leaked client threads: {leaked!r}"
        )


@pytest.fixture
def system_factory(
    tmp_path: Path,
) -> Iterator[Callable[[str], _RunningSystem]]:
    systems: list[_RunningSystem] = []

    def create(mode: str) -> _RunningSystem:
        system = _RunningSystem(
            tmp_path / f"wal-{mode}",
            mode,
        )
        systems.append(system)
        return system

    try:
        yield create
    finally:
        for system in systems:
            system.close()


def _assert_listener_refuses_connections(
    address: tuple[str, int],
) -> None:
    try:
        probe = _connect(address, 1.0)
    except OSError as exc:
        assert exc.errno == errno.ECONNREFUSED
    else:
        probe.close()
        pytest.fail(
            "listener accepted a connection after shutdown began"
        )


def _physical_messages(directory: Path) -> list[Any]:
    messages: list[Any] = []
    expected_lsn = 1
    paths = sorted(directory.glob("wal-*.log"))
    assert paths

    for segment_index, path in enumerate(paths):
        assert path.name == (
            f"wal-{segment_index:08d}.log"
        )
        data = path.read_bytes()

        assert len(data) >= SEGMENT_HEADER.size
        assert SEGMENT_HEADER.unpack_from(data) == (
            SEGMENT_MAGIC,
            SEGMENT_VERSION,
            expected_lsn,
        )

        offset = SEGMENT_HEADER.size

        while offset < len(data):
            assert len(data) - offset >= RECORD_HEADER.size

            checksum, length, lsn, record_type = (
                RECORD_HEADER.unpack_from(data, offset)
            )
            assert 9 <= length <= 9 + MAX_RECORD_PAYLOAD

            end = offset + 8 + length
            assert end <= len(data), (
                "graceful exit left a torn WAL tail"
            )

            calculated = zlib.crc32(
                memoryview(data)[offset + 4:end]
            ) & 0xFFFFFFFF

            assert checksum == calculated
            assert lsn == expected_lsn
            assert record_type == RecordType.MESSAGE

            record = WalRecord(
                lsn,
                record_type,
                data[offset + RECORD_HEADER.size:end],
            )
            messages.append(decode_message(record))

            expected_lsn += 1
            offset = end

        assert offset == len(data)

    return messages


def test_sigterm_drains_five_busy_clients_and_preserves_every_ack(
    system_factory: Callable[[str], _RunningSystem],
) -> None:
    system = system_factory("graceful")
    address = system.start_load()

    started = time.monotonic()
    system.process.send_signal(signal.SIGTERM)

    draining = system.reports.wait(
        "draining",
        SHUTDOWN_MS / 1000.0,
    )
    assert draining["signal_count"] == 1
    assert draining["listener_closed"]
    assert draining["pending_wal"] > 0
    assert draining["fsync_blocked"]

    _assert_listener_refuses_connections(address)

    finished = system.reports.wait(
        "finished",
        SHUTDOWN_MS / 1000.0 + 1.0,
    )
    assert system.process.wait(1.0) == 0

    elapsed = time.monotonic() - started
    assert elapsed <= SHUTDOWN_MS / 1000.0 + 1.0
    assert finished["status"] == 0
    assert finished["elapsed"] <= SHUTDOWN_MS / 1000.0
    assert finished["pending_wal"] == 0
    assert finished["pending_router"] == 0
    assert finished["connections"] == 0

    system.join_clients()

    # Inspect bytes before recovery can repair or truncate anything.
    messages = _physical_messages(system.directory)
    by_key = {
        (message.user, message.client_msg_id): message
        for message in messages
    }

    total = CLIENT_COUNT * MESSAGES_PER_CLIENT
    assert len(messages) == len(by_key) == total
    assert [
        message.commit_id for message in messages
    ] == list(range(1, total + 1))
    assert [
        message.seq for message in messages
    ] == list(range(1, total + 1))

    for result in system.results:
        assert result.shutdown_seen
        assert (
            len(result.acknowledgments)
            == MESSAGES_PER_CLIENT
        )
        assert result.delivered_sequences == set(
            range(1, total + 1)
        )

        for message_id, acknowledged_seq in (
            result.acknowledgments.items()
        ):
            message = by_key[
                (f"client_{result.index}", message_id)
            ]
            assert message.seq == acknowledged_seq
            assert message.origin_node == NODE_ID
            assert message.room == ROOM
            assert message.request_id == 1000 + message_id
            assert message.body == _body(
                result.index,
                message_id,
            )


def test_second_sigint_aborts_while_a_wal_fsync_is_blocked(
    system_factory: Callable[[str], _RunningSystem],
) -> None:
    system = system_factory("panic")
    system.start_load()
    system.panic_expected.set()

    system.process.send_signal(signal.SIGINT)

    # Identical POSIX signals can coalesce. Observe the first delivery before
    # immediately sending the second interrupt.
    draining = system.reports.wait("draining", 2.0)

    assert draining["signal_count"] == 1
    assert draining["listener_closed"]
    assert draining["pending_wal"] > 0
    assert draining["fsync_blocked"]
    assert system.process.poll() is None

    started = time.monotonic()
    system.process.send_signal(signal.SIGINT)

    assert system.process.wait(2.0) == 1
    assert (
        time.monotonic() - started
        < SHUTDOWN_MS / 1000.0
    )

    system.join_clients()

    assert not any(
        event["event"] == "finished"
        for event in system.reports.events
    )


if __name__ == "__main__":
    if (
        len(sys.argv) != 4
        or sys.argv[1] != "--shutdown-server"
    ):
        raise SystemExit(
            "expected --shutdown-server WAL_DIRECTORY MODE"
        )

    os.set_blocking(sys.stdout.fileno(), False)
    server = _Server(Path(sys.argv[2]), sys.argv[3])

    try:
        status = server.run()
    finally:
        server.close()

    raise SystemExit(status)