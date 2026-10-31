from __future__ import annotations

import errno
import math
import os
import signal
import socket
import struct
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import IntEnum
from types import FrameType
from typing import TYPE_CHECKING, NoReturn, TypeAlias

from victory.storage.writer_thread import WalWriter, WriterState

if TYPE_CHECKING:
    from victory.core.router import Action, Router
    from victory.net.backends import Backend, Event

READ = 1
MAX_SHUTDOWN_MS = 5000

_REAP_INTERVAL = 0.01
_HEADER = struct.Struct("!HBBBBII")
_SHUTDOWN = struct.Struct("!BI")
_ERROR = struct.Struct("!HBH")
_ERROR_MESSAGE = b"server is shutting down"

_ROUTINE_ERRORS = frozenset(
    (
        errno.EBADF,
        errno.ENOENT,
        errno.ENOTCONN,
        errno.ECONNRESET,
        errno.EPIPE,
        errno.ETIMEDOUT,
    )
)

SignalHandler: TypeAlias = (
    int | Callable[[int, FrameType | None], None]
)


class ShutdownState(IntEnum):
    RUNNING = 0
    DRAINING = 1
    FLUSHING = 2
    EXIT = 3


@dataclass(frozen=True, slots=True)
class DrainConnection:
    """Bind shutdown operations to an existing loop-owned connection.

    enqueue stages bytes and updates write interest without waiting for I/O.
    close performs normal reactor, router, and connection registry cleanup.
    fileno returns -1 after closure. Every callback must be non-blocking.
    """

    session_id: int
    fileno: Callable[[], int]
    pending_bytes: Callable[[], int]
    enqueue: Callable[[bytes], None]
    close: Callable[[], None]

    def __post_init__(self) -> None:
        if type(self.session_id) is not int or self.session_id < 0:
            raise ValueError(
                "session_id must be a nonnegative integer"
            )

        for callback in (
            self.fileno,
            self.pending_bytes,
            self.enqueue,
            self.close,
        ):
            if not callable(callback):
                raise TypeError(
                    "connection operations must be callable"
                )


def _packet(
    frame_type: int,
    request_id: int,
    payload: bytes,
) -> bytes:
    return _HEADER.pack(
        0xCE57,
        1,
        frame_type,
        0,
        0,
        request_id,
        len(payload),
    ) + payload


def _nonblocking_pipe() -> tuple[int, int]:
    if hasattr(os, "pipe2"):
        return os.pipe2(os.O_NONBLOCK | os.O_CLOEXEC)

    reader, writer = os.pipe()

    try:
        os.set_blocking(reader, False)
        os.set_blocking(writer, False)
        os.set_inheritable(reader, False)
        os.set_inheritable(writer, False)
    except BaseException:
        os.close(reader)
        os.close(writer)
        raise

    return reader, writer


class ShutdownCoordinator:
    """Coordinate shutdown exclusively on the reactor thread.

    Forward coordinator and WAL readiness events to handle_event. This
    instance owns WAL completion dispatch; do not also drain the writer
    elsewhere. Call tick after each reactor pass and bound the reactor's
    poll timeout with get_next_timeout.

    Wrap command routing with dispatch_command so JOIN and MSG cannot bypass
    draining. apply_actions executes the router's normal outbound intents.
    flush_pending_wal retries accepted AppendWalAction admission backlog.
    It may be omitted when every accepted action is already admitted.

    connections is the live reactor-owned mapping. Bind DrainConnection
    callbacks to existing connection methods and teardown operations.
    on_exit stops the master loop; exit_code supplies process status.
    """

    def __init__(
        self,
        backend: Backend,
        writer: WalWriter,
        router: Router,
        connections: Mapping[int, DrainConnection],
        listeners: Sequence[socket.socket],
        *,
        apply_actions: Callable[[list[Action]], None],
        flush_pending_wal: Callable[[], None] | None = None,
        on_exit: Callable[[int], None] | None = None,
        timeout_ms: int = MAX_SHUTDOWN_MS,
        clock: Callable[[], float] = time.monotonic,
        abort: Callable[[int], NoReturn] = os._exit,
        install_signals: bool = True,
    ) -> None:
        if (
            type(timeout_ms) is not int
            or not 0 <= timeout_ms <= MAX_SHUTDOWN_MS
        ):
            raise ValueError(
                "timeout_ms must be an integer from 0 through 5000"
            )

        if writer.state != WriterState.RUNNING:
            raise ValueError(
                "start the WAL writer before the shutdown coordinator"
            )

        self._owner = threading.get_ident()
        self._backend = backend
        self._writer = writer
        self._router = router
        self._connections = connections
        self._listeners = list(listeners)
        self._apply_actions = apply_actions
        self._flush_pending_wal = flush_pending_wal
        self._on_exit = on_exit
        self._timeout_ms = timeout_ms
        self._clock = clock
        self._abort = abort

        self._state = ShutdownState.RUNNING
        self._exit_code = 0
        self._deadline: float | None = None

        self._signal_count = 0
        self._wakeup_failed = 0
        self._storage_failed = False

        self._wal_closed = False
        self._wal_reap_pending = False
        self._closed_sessions: set[int] = set()
        self._errors: deque[str] = deque(maxlen=16)

        self._previous_handlers: dict[
            signal.Signals, SignalHandler
        ] = {}

        self._reader = -1
        self._wakeup_writer = -1
        self._registered = False
        self._closed = False
        self._exit_notified = False

        for listener in self._listeners:
            listener.setblocking(False)

        try:
            self._reader, self._wakeup_writer = _nonblocking_pipe()
            backend.register(self._reader, READ, self)
            self._registered = True

            if install_signals:
                self.install_signal_handlers()
        except BaseException:
            self.close()
            raise

    @property
    def state(self) -> ShutdownState:
        return self._state

    @property
    def finished(self) -> bool:
        return self._state == ShutdownState.EXIT

    @property
    def exit_code(self) -> int:
        return self._exit_code

    @property
    def deadline(self) -> float | None:
        return self._deadline

    @property
    def signal_count(self) -> int:
        return self._signal_count

    @property
    def errors(self) -> list[str]:
        return list(self._errors)

    def fileno(self) -> int:
        return self._reader

    def _check_owner(self) -> None:
        if threading.get_ident() != self._owner:
            raise RuntimeError(
                "shutdown operations belong to the reactor thread"
            )

    def _now(self, now: float | None = None) -> float:
        value = self._clock() if now is None else now

        if not math.isfinite(value):
            raise ValueError("monotonic time must be finite")

        return value

    def _remember(self, exc: Exception) -> None:
        self._errors.append(
            f"{type(exc).__name__}: {str(exc)[:256]}"
        )

        if (
            not isinstance(exc, OSError)
            or exc.errno not in _ROUTINE_ERRORS
        ):
            self._exit_code = 1

    def _handle_signal(
        self,
        signum: int,
        frame: FrameType | None,
    ) -> None:
        # Signal delivery only publishes flags and a notification byte.
        self._signal_count = (
            1 if self._signal_count == 0 else 2
        )

        while True:
            try:
                if os.write(self._wakeup_writer, b"\x00") != 1:
                    self._wakeup_failed = 1
                return
            except InterruptedError:
                continue
            except BlockingIOError:
                return
            except OSError:
                self._wakeup_failed = 1
                return

    def install_signal_handlers(self) -> None:
        self._check_owner()

        if self._closed:
            raise RuntimeError("shutdown coordinator is closed")

        if threading.current_thread() is not threading.main_thread():
            raise RuntimeError(
                "signal handlers must be installed on the main thread"
            )

        if self._previous_handlers:
            return

        try:
            for signum in (signal.SIGTERM, signal.SIGINT):
                previous = signal.getsignal(signum)

                if previous is None:
                    raise RuntimeError(
                        "cannot replace an unknown native signal handler"
                    )

                if isinstance(
                    getattr(previous, "__self__", None),
                    ShutdownCoordinator,
                ):
                    raise RuntimeError(
                        "another shutdown coordinator owns process signals"
                    )

                signal.signal(signum, self._handle_signal)
                self._previous_handlers[signum] = previous
        except BaseException:
            self._restore_signal_handlers()
            raise

    def _restore_signal_handlers(self) -> None:
        for signum, previous in list(
            self._previous_handlers.items()
        ):
            if signal.getsignal(signum) == self._handle_signal:
                signal.signal(signum, previous)

            del self._previous_handlers[signum]

    def request_shutdown(self) -> None:
        self._check_owner()

        if self._closed or self.finished:
            return

        self._handle_signal(0, None)

    def _abort_on_second_signal(self) -> None:
        if self._signal_count >= 2:
            self._state = ShutdownState.EXIT
            self._exit_code = 1
            self._abort(1)
            raise SystemExit(1)

    def _drain_wakeup(self) -> None:
        while True:
            self._abort_on_second_signal()

            try:
                data = os.read(self._reader, 4096)
            except InterruptedError:
                continue
            except BlockingIOError:
                return
            except OSError as exc:
                self._wakeup_failed = 1
                self._remember(exc)
                return

            if not data:
                self._wakeup_failed = 1
                return

    def _unregister(self, fd: int) -> None:
        if fd < 0:
            return

        try:
            self._backend.unregister(fd)
        except KeyError:
            return
        except OSError as exc:
            self._remember(exc)

    def _close_listeners(self) -> None:
        listeners, self._listeners = self._listeners, []

        for listener in listeners:
            self._abort_on_second_signal()

            try:
                self._unregister(listener.fileno())
            finally:
                try:
                    listener.close()
                except OSError as exc:
                    self._remember(exc)

    def _snapshot(self) -> list[DrainConnection]:
        result: list[DrainConnection] = []

        for session_id, connection in list(
            self._connections.items()
        ):
            self._abort_on_second_signal()

            if session_id != connection.session_id:
                raise ValueError(
                    "connection registry key does not match session_id"
                )

            if session_id not in self._closed_sessions:
                result.append(connection)

        return result

    def _close_connection(
        self,
        connection: DrainConnection,
    ) -> None:
        if connection.session_id in self._closed_sessions:
            return

        self._closed_sessions.add(connection.session_id)

        try:
            self._unregister(connection.fileno())
        except Exception as exc:
            self._remember(exc)
        finally:
            try:
                connection.close()
            except Exception as exc:
                self._remember(exc)

    def _close_connections(self) -> None:
        for connection in self._snapshot():
            self._abort_on_second_signal()
            self._close_connection(connection)

    def _enqueue(
        self,
        connection: DrainConnection,
        packet: bytes,
    ) -> None:
        try:
            connection.enqueue(packet)
        except Exception as exc:
            self._remember(exc)
            self._close_connection(connection)

    def _service_wal(self) -> None:
        try:
            actions = self._writer.drain_actions(self._router)

            if actions:
                self._apply_actions(actions)
        except Exception as exc:
            self._remember(exc)
            self._storage_failed = True
            self._exit_code = 1

        if self._writer.state == WriterState.FAILED:
            self._storage_failed = True
            self._exit_code = 1

    def _begin_draining(self, now: float) -> None:
        self._state = ShutdownState.DRAINING
        self._deadline = now + self._timeout_ms / 1000.0

        self._close_listeners()

        packet = _packet(
            0x09,
            0,
            _SHUTDOWN.pack(0, self._timeout_ms),
        )

        for connection in self._snapshot():
            self._abort_on_second_signal()

            if self._now() >= self._deadline:
                self._force_deadline()
                return

            self._enqueue(connection, packet)

    def _deadline_expired(self) -> bool:
        if (
            self._deadline is not None
            and self._now() >= self._deadline
        ):
            self._force_deadline()
            return True

        return False

    def rejection_packet(
        self,
        frame_type: int,
        request_id: int,
    ) -> bytes | None:
        self._check_owner()

        if (
            not isinstance(frame_type, int)
            or isinstance(frame_type, bool)
        ):
            raise TypeError("frame_type must be an integer")

        if (
            type(request_id) is not int
            or not 0 <= request_id <= 0xFFFFFFFF
        ):
            raise ValueError("request_id must fit u32")

        draining = (
            self._state != ShutdownState.RUNNING
            or self._signal_count != 0
            or self._storage_failed
        )

        if not draining or frame_type not in (0x02, 0x04):
            return None

        payload = (
            _ERROR.pack(17, 0, len(_ERROR_MESSAGE))
            + _ERROR_MESSAGE
        )
        return _packet(0x08, request_id, payload)

    def dispatch_command(
        self,
        session_id: int,
        frame_type: int,
        request_id: int,
        dispatch: Callable[[], list[Action] | None],
    ) -> bool:
        """Run the command and apply returned actions, or return False.

        A dispatch callback that applies its own actions returns None.
        """
        self._check_owner()
        self._abort_on_second_signal()

        if self.finished or self._closed:
            return False

        if (
            self._state == ShutdownState.RUNNING
            and self._signal_count
        ):
            self.tick()

        if self.finished or self._deadline_expired():
            return False

        packet = self.rejection_packet(frame_type, request_id)

        if packet is None:
            actions = dispatch()

            if actions:
                self._apply_actions(actions)

            return True

        connection = self._connections.get(session_id)

        if (
            connection is not None
            and session_id not in self._closed_sessions
        ):
            self._enqueue(connection, packet)

        return False

    def _advance_wal_shutdown(self) -> None:
        if self._wal_closed:
            return

        if self._writer.state == WriterState.RUNNING:
            if self._flush_pending_wal is not None:
                try:
                    self._flush_pending_wal()
                except Exception as exc:
                    self._remember(exc)
                    self._storage_failed = True
                    self._exit_code = 1

            if (
                self._writer.pending_count
                or self._router.pending_count
            ):
                return

            self._writer.request_stop()

        try:
            self._wal_closed = self._writer.close(0.0)
            self._wal_reap_pending = not self._wal_closed
        except Exception as exc:
            self._remember(exc)
            self._storage_failed = True
            self._exit_code = 1
            self._wal_reap_pending = True

        self._service_wal()

    def _outbound_empty(self) -> bool:
        empty = True

        for connection in self._snapshot():
            self._abort_on_second_signal()

            if self._deadline_expired():
                return False

            try:
                pending = connection.pending_bytes()

                if type(pending) is not int or pending < 0:
                    raise ValueError(
                        "pending_bytes must return a nonnegative integer"
                    )

                if pending:
                    empty = False
            except Exception as exc:
                self._remember(exc)
                self._close_connection(connection)

        return empty

    def _notify_exit(self) -> None:
        if self._exit_notified:
            return

        self._exit_notified = True

        if self._on_exit is not None:
            self._on_exit(self._exit_code)

    def _finish(self) -> None:
        self._abort_on_second_signal()
        self._close_connections()
        self._state = ShutdownState.EXIT
        self.close()
        self._notify_exit()

    def _force_deadline(self) -> None:
        self._exit_code = 1
        self._close_listeners()
        self._close_connections()

        if not self._wal_closed:
            try:
                self._writer.request_stop()
                self._wal_closed = self._writer.close(0.0)
            except Exception as exc:
                self._remember(exc)

        self._state = ShutdownState.EXIT

        if not self._wal_closed:
            # Python cannot cancel a thread blocked inside write or fsync.
            self._abort(1)
            raise SystemExit(1)

        self.close()
        self._notify_exit()

    def tick(
        self,
        now: float | None = None,
    ) -> ShutdownState:
        self._check_owner()
        self._abort_on_second_signal()

        if self.finished or self._closed:
            return self._state

        if self._wakeup_failed:
            self._force_deadline()
            return self._state

        current = self._now(now)

        if (
            self._deadline is not None
            and current >= self._deadline
        ):
            self._force_deadline()
            return self._state

        if (
            self._state == ShutdownState.RUNNING
            and self._signal_count
        ):
            self._begin_draining(current)
            return self._state

        self._service_wal()
        self._abort_on_second_signal()

        if self._deadline_expired():
            return self._state

        if self._state == ShutdownState.RUNNING:
            if self._storage_failed:
                self._begin_draining(
                    max(current, self._now())
                )

            return self._state

        if self._state == ShutdownState.DRAINING:
            self._state = ShutdownState.FLUSHING

        self._advance_wal_shutdown()
        self._abort_on_second_signal()

        if self._deadline_expired():
            return self._state

        if self._wal_closed and not self._router.pending_count:
            if (
                self._outbound_empty()
                and not self._deadline_expired()
            ):
                self._finish()

        return self._state

    def handle_event(self, event: Event) -> bool:
        self._check_owner()
        self._abort_on_second_signal()

        if self.finished or self._closed:
            return False

        if event.fd == self._reader and event.data is self:
            self._drain_wakeup()
        elif (
            event.fd == self._writer.fileno()
            and event.data is self._writer
        ):
            # tick consumes durability completions and stages router actions.
            self._abort_on_second_signal()
        else:
            return False

        self.tick()
        return True

    def get_next_timeout(
        self,
        now: float | None = None,
    ) -> float | None:
        self._check_owner()

        if self.finished:
            return 0.0

        if self._signal_count >= 2 or self._wakeup_failed:
            return 0.0

        if self._state == ShutdownState.RUNNING:
            if self._signal_count or self._storage_failed:
                return 0.0
            return None

        if self._state == ShutdownState.DRAINING:
            return 0.0

        if self._deadline is None:
            raise RuntimeError("draining state has no deadline")

        remaining = max(
            0.0,
            self._deadline - self._now(now),
        )

        # WriterStopped can precede the native thread's final return.
        # Retry non-blocking reaping without spinning after WAL unregister.
        if self._wal_reap_pending:
            return min(remaining, _REAP_INTERVAL)

        return remaining

    def close(self) -> None:
        """Release signal registrations and self-pipe descriptors."""
        self._check_owner()

        if self._closed:
            return

        self._restore_signal_handlers()

        if self._registered:
            self._unregister(self._reader)
            self._registered = False

        self._closed = True

        for name in ("_reader", "_wakeup_writer"):
            fd = getattr(self, name)
            setattr(self, name, -1)

            if fd >= 0:
                try:
                    os.close(fd)
                except OSError as exc:
                    self._remember(exc)