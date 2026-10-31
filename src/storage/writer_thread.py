from __future__ import annotations

import errno
import select
import socket
import threading
from collections import deque
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING, TypeAlias

from victory.storage.wal import (
    WalError,
    WalRecord,
    WriteAheadLog,
    encode_message,
)

if TYPE_CHECKING:
    from victory.core.router import Action, AppendWalAction, Router
    from victory.net.backends import Backend, Event

READ = 1


class WriterUnavailableError(WalError):
    """The writer is stopping, failed, or cannot accept this request."""


class WriterState(IntEnum):
    NEW = 0
    RUNNING = 1
    STOPPING = 2
    STOPPED = 3
    FAILED = 4
    CLOSED = 5


@dataclass(frozen=True, slots=True)
class DurableBatch:
    first_lsn: int
    last_lsn: int
    record_count: int
    bytes_written: int


@dataclass(frozen=True, slots=True)
class WriterFailure:
    failed_lsn: int
    last_durable_lsn: int
    error_number: int | None
    error_type: str
    message: str


@dataclass(frozen=True, slots=True)
class WriterStopped:
    last_durable_lsn: int
    failed: bool


Completion: TypeAlias = DurableBatch | WriterFailure | WriterStopped


@dataclass(frozen=True, slots=True)
class _Stop:
    """FIFO shutdown marker placed after all accepted requests."""


Request: TypeAlias = WalRecord | _Stop


def _notify(sock: socket.socket) -> None:
    while True:
        try:
            if sock.send(b"\x00") != 1:
                raise OSError(
                    errno.EPIPE,
                    "WAL notification socket closed",
                )
            return
        except InterruptedError:
            continue
        except BlockingIOError:
            # An unread notification already makes the peer readable.
            return


def _drain_wakeup(sock: socket.socket) -> bool:
    """Return False on EOF; notification bytes carry no application data."""
    while True:
        try:
            data = sock.recv(4096)
        except InterruptedError:
            continue
        except BlockingIOError:
            return True

        if not data:
            return False


def _failure(
    exc: BaseException,
    failed_lsn: int,
    durable_lsn: int,
) -> WriterFailure:
    number = exc.errno if isinstance(exc, OSError) else None

    return WriterFailure(
        failed_lsn=failed_lsn,
        last_durable_lsn=durable_lsn,
        error_number=number,
        error_type=type(exc).__name__,
        message=str(exc)[:1024],
    )


def _post(
    completions: deque[Completion],
    wakeup: socket.socket,
    completion: Completion,
) -> None:
    completions.append(completion)
    _notify(wakeup)


def _worker_main(
    log: WriteAheadLog,
    requests: deque[Request],
    completions: deque[Completion],
    request_reader: socket.socket,
    completion_writer: socket.socket,
    max_batch_records: int,
    max_batch_bytes: int,
    initial_lsn: int,
) -> None:
    """The worker receives no router, client socket, backend, or ACK callback."""
    durable_lsn = initial_lsn
    failed_lsn = initial_lsn + 1
    failed = False
    claimed = False
    pending: WalRecord | None = None
    stopping = False

    try:
        log.claim()
        claimed = True

        while not stopping:
            if pending is None:
                try:
                    request = requests.popleft()
                except IndexError:
                    while True:
                        try:
                            select.select([request_reader], [], [])
                            break
                        except InterruptedError:
                            continue

                    channel_open = _drain_wakeup(request_reader)

                    if not channel_open and not requests:
                        raise OSError(
                            errno.EPIPE,
                            "WAL request channel closed without a stop marker",
                        )
                    continue

                if isinstance(request, _Stop):
                    break

                pending = request

            batch = [pending]
            byte_count = pending.wire_size
            failed_lsn = pending.lsn
            pending = None

            while len(batch) < max_batch_records:
                try:
                    request = requests.popleft()
                except IndexError:
                    break

                if isinstance(request, _Stop):
                    stopping = True
                    break

                if byte_count + request.wire_size > max_batch_bytes:
                    pending = request
                    break

                batch.append(request)
                byte_count += request.wire_size

            log.prepare_batch(byte_count)
            durable_lsn = log.append_batch(batch)
            failed_lsn = durable_lsn + 1

            # append_batch returns only after the entire batch is fsynced.
            _post(
                completions,
                completion_writer,
                DurableBatch(
                    first_lsn=batch[0].lsn,
                    last_lsn=durable_lsn,
                    record_count=len(batch),
                    bytes_written=byte_count,
                ),
            )

    except BaseException as exc:
        failed = True
        completions.append(
            _failure(exc, failed_lsn, durable_lsn)
        )

        try:
            _notify(completion_writer)
        except OSError:
            failed = True

    finally:
        if claimed:
            try:
                log.close()
            except BaseException as exc:
                failed = True
                completions.append(
                    _failure(
                        exc,
                        durable_lsn + 1,
                        durable_lsn,
                    )
                )

        completions.append(
            WriterStopped(
                last_durable_lsn=durable_lsn,
                failed=failed,
            )
        )

        try:
            _notify(completion_writer)
        except OSError:
            failed = True
        finally:
            request_reader.close()
            completion_writer.close()


class WalWriter:
    """Bounded single-producer/single-consumer CPython deque bridge.

    Construct after synchronous recovery and before running the reactor.
    Backend registration uses data=self. Dispatch its readiness event to
    handle_event(event, router) to release durable actions.

    Use either drain_actions or manually route drain_completions, never both.

    request_stop and close(timeout=0) do not wait for disk. A nonzero close
    timeout is intended for shutdown after the active reactor loop has ended.
    """

    def __init__(
        self,
        log: WriteAheadLog,
        backend: Backend,
        *,
        max_pending_records: int = 4096,
        max_pending_bytes: int = 64 * 1024 * 1024,
        max_batch_records: int = 128,
        max_batch_bytes: int = 1024 * 1024,
    ) -> None:
        for name, value in (
            ("max_pending_records", max_pending_records),
            ("max_pending_bytes", max_pending_bytes),
            ("max_batch_records", max_batch_records),
            ("max_batch_bytes", max_batch_bytes),
        ):
            if type(value) is not int or value <= 0:
                raise ValueError(
                    f"{name} must be a positive integer"
                )

        self._owner = threading.get_ident()
        self._backend = backend
        self._log = log
        self._state = WriterState.NEW

        self._requests: deque[Request] = deque()
        self._completions: deque[Completion] = deque()
        self._outstanding: dict[int, int] = {}
        self._outstanding_bytes = 0

        self._max_pending_records = max_pending_records
        self._max_pending_bytes = max_pending_bytes
        self._max_batch_records = max_batch_records
        self._max_batch_bytes = min(
            max_batch_bytes,
            log.batch_capacity,
        )

        self._initial_lsn = log.last_lsn
        self._next_lsn = self._initial_lsn + 1
        self._durable_lsn = self._initial_lsn

        self._routing_failed = False
        self._stop_requested = False
        self._local_failure: WriterFailure | None = None
        self._thread: threading.Thread | None = None
        self._registered = False

        self._request_reader, self._request_writer = socket.socketpair()

        try:
            (
                self._completion_reader,
                self._completion_writer,
            ) = socket.socketpair()
        except BaseException:
            self._request_reader.close()
            self._request_writer.close()
            raise

        try:
            for sock in (
                self._request_reader,
                self._request_writer,
                self._completion_reader,
                self._completion_writer,
            ):
                sock.setblocking(False)

            backend.register(
                self._completion_reader.fileno(),
                READ,
                self,
            )
            self._registered = True

        except BaseException:
            self._request_reader.close()
            self._request_writer.close()
            self._completion_reader.close()
            self._completion_writer.close()
            raise

    def _check_owner(self) -> None:
        if threading.get_ident() != self._owner:
            raise WriterUnavailableError(
                "WAL facade must be used on its event-loop owner thread"
            )

    @property
    def state(self) -> WriterState:
        return self._state

    @property
    def pending_count(self) -> int:
        return len(self._outstanding)

    @property
    def pending_bytes(self) -> int:
        return self._outstanding_bytes

    @property
    def durable_lsn(self) -> int:
        """The durable prefix observed through the completion deque."""
        return self._durable_lsn

    def fileno(self) -> int:
        return self._completion_reader.fileno()

    def start(self) -> None:
        self._check_owner()

        if self._state != WriterState.NEW:
            raise WriterUnavailableError(
                "WAL writer can only be started once"
            )

        thread = threading.Thread(
            name="victory-wal",
            target=_worker_main,
            args=(
                self._log,
                self._requests,
                self._completions,
                self._request_reader,
                self._completion_writer,
                self._max_batch_records,
                self._max_batch_bytes,
                self._initial_lsn,
            ),
            daemon=False,
        )

        self._log.handoff()

        try:
            thread.start()
        except BaseException:
            self._log.claim()
            raise

        self._thread = thread
        self._state = WriterState.RUNNING

    def _wake_worker(self) -> None:
        try:
            _notify(self._request_writer)
        except OSError as exc:
            if self._local_failure is None:
                failed_lsn = next(
                    iter(self._outstanding),
                    self._next_lsn,
                )
                self._local_failure = _failure(
                    exc,
                    failed_lsn,
                    self._durable_lsn,
                )

            self._state = WriterState.FAILED

            if not self._stop_requested:
                self._requests.append(_Stop())
                self._stop_requested = True

            self._request_writer.close()

    def submit(self, action: AppendWalAction) -> bool:
        """On False, retry this action before submitting any later LSN."""
        self._check_owner()

        if self._state != WriterState.RUNNING:
            raise WriterUnavailableError(
                "WAL writer is not accepting records"
            )

        return self.submit_record(encode_message(action.record))

    def submit_record(self, record: WalRecord) -> bool:
        self._check_owner()

        if self._state != WriterState.RUNNING:
            raise WriterUnavailableError(
                "WAL writer is not accepting records"
            )

        if record.lsn != self._next_lsn:
            raise ValueError(
                f"expected submission LSN {self._next_lsn}, "
                f"received {record.lsn}"
            )

        if record.wire_size > self._log.batch_capacity:
            raise ValueError("record exceeds segment data capacity")

        if record.wire_size > self._max_pending_bytes:
            raise ValueError(
                "record exceeds the entire pending byte budget"
            )

        if (
            len(self._outstanding) >= self._max_pending_records
            or (
                self._outstanding_bytes + record.wire_size
                > self._max_pending_bytes
            )
        ):
            return False

        # Account before publication: the worker may immediately pop the record.
        self._outstanding[record.lsn] = record.wire_size
        self._outstanding_bytes += record.wire_size
        self._next_lsn += 1

        self._requests.append(record)
        self._wake_worker()
        return True

    def request_stop(self) -> None:
        self._check_owner()

        if self._state == WriterState.RUNNING:
            self._state = WriterState.STOPPING

        if self._thread is not None and not self._stop_requested:
            self._stop_requested = True
            self._requests.append(_Stop())
            self._wake_worker()

    def _unregister(self) -> None:
        if self._registered:
            self._backend.unregister(self.fileno())
            self._registered = False

    def drain_completions(self) -> list[Completion]:
        """Consume notifications and retire admission accounting on the loop."""
        self._check_owner()

        if self._state != WriterState.CLOSED:
            try:
                _drain_wakeup(self._completion_reader)
            except OSError as exc:
                if self._local_failure is None:
                    self._local_failure = _failure(
                        exc,
                        self._durable_lsn + 1,
                        self._durable_lsn,
                    )

                self._state = WriterState.FAILED
                self.request_stop()

        result: list[Completion] = []

        if self._local_failure is not None:
            result.append(self._local_failure)
            self._local_failure = None

        while True:
            try:
                completion = self._completions.popleft()
            except IndexError:
                break

            if isinstance(completion, DurableBatch):
                if (
                    completion.first_lsn != self._durable_lsn + 1
                    or (
                        completion.record_count
                        != completion.last_lsn - completion.first_lsn + 1
                    )
                    or completion.record_count <= 0
                ):
                    raise WalError(
                        "worker returned an invalid durability prefix"
                    )

                total = 0

                for lsn in range(
                    completion.first_lsn,
                    completion.last_lsn + 1,
                ):
                    size = self._outstanding.pop(lsn, None)

                    if size is None:
                        raise WalError(
                            "worker completed an unsubmitted record"
                        )

                    total += size

                if total != completion.bytes_written:
                    raise WalError(
                        "worker completion byte accounting mismatch"
                    )

                self._outstanding_bytes -= total
                self._durable_lsn = completion.last_lsn

            elif isinstance(completion, WriterFailure):
                if self._state != WriterState.CLOSED:
                    self._state = WriterState.FAILED

            else:
                # WriterStopped is published after the worker closes the WAL.
                self._requests.clear()
                self._outstanding.clear()
                self._outstanding_bytes = 0

                if self._state not in (
                    WriterState.FAILED,
                    WriterState.CLOSED,
                ):
                    self._state = (
                        WriterState.FAILED
                        if completion.failed
                        else WriterState.STOPPED
                    )

                self._unregister()

            result.append(completion)

        return result

    def drain_actions(self, router: Router) -> list[Action]:
        """Release ACKs and deliveries exclusively from durability completions."""
        actions: list[Action] = []

        for completion in self.drain_completions():
            if (
                isinstance(completion, DurableBatch)
                and not self._routing_failed
            ):
                for lsn in range(
                    completion.first_lsn,
                    completion.last_lsn + 1,
                ):
                    actions.extend(router.wal_committed(lsn))

            elif (
                isinstance(completion, WriterFailure)
                and not self._routing_failed
            ):
                self._routing_failed = True

                if router.pending_count:
                    actions.extend(
                        router.wal_failed(
                            completion.failed_lsn,
                            completion.message,
                        )
                    )
                else:
                    actions.extend(router.begin_shutdown(0))

        return actions

    def handle_event(
        self,
        event: Event,
        router: Router,
    ) -> list[Action]:
        self._check_owner()

        if event.fd != self.fileno() or event.data is not self:
            raise ValueError(
                "event does not belong to this WAL writer"
            )

        return self.drain_actions(router)

    def close(self, timeout: float = 0.0) -> bool:
        """Return False while the worker still owns disk resources."""
        self._check_owner()

        if timeout < 0:
            raise ValueError("close timeout must be nonnegative")

        if self._state == WriterState.CLOSED:
            return True

        if self._thread is None:
            self._log.close()
            self._request_reader.close()
            self._completion_writer.close()
        else:
            self.request_stop()
            self._thread.join(timeout)

            if self._thread.is_alive():
                return False

        self._unregister()
        self._request_writer.close()
        self._completion_reader.close()
        self._state = WriterState.CLOSED
        return True