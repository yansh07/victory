"""Single-owner socket staging, streaming decoding, and backpressure.

Connection owns its socket and backend registration. The reactor supplies
its shared scratch bytearray and dispatches Event.data.handle_events().
Adopting this class requires replacing M2's private client record and
dispatch with Connection instances.
"""

from __future__ import annotations

import errno
import socket
from collections import deque
from dataclasses import dataclass
from enum import IntEnum
from struct import Struct
from typing import Callable, TypeAlias, cast

from ..protocol.decoder import FrameDecoder
from ..protocol.frame import (
    HEADER_SIZE,
    MAX_PAYLOAD,
    Frame,
    FrameType,
    ProtocolError,
    validate_max_payload,
)
from .backends import (
    ERROR,
    HANGUP,
    PEER_CLOSED,
    READ,
    WRITE,
    Backend,
)

READ_BUDGET = 64 * 1024
WRITE_BUDGET = 64 * 1024
IO_OPERATION_BUDGET = 64

INITIAL_INPUT_CAPACITY = 4096
LOW_WATERMARK = 64 * 1024
SOFT_LIMIT = 256 * 1024
HARD_LIMIT = 1024 * 1024

SLOW_CONSUMER = 14

_ERROR_PREFIX = Struct("!HBH")
_WOULD_BLOCK = frozenset((errno.EAGAIN, errno.EWOULDBLOCK))

OutputBuffer: TypeAlias = bytes | memoryview


class ConnectionState(IntEnum):
    OPEN = 1
    DRAINING = 2
    CLOSED = 3


class FailureKind(IntEnum):
    NETWORK = 1
    BACKEND = 2
    PROTOCOL = 3
    SLOW_CONSUMER = 4


@dataclass(frozen=True, slots=True)
class ConnectionFailure:
    """Boundary failure metadata without retained exception tracebacks."""

    kind: FailureKind
    operation: str
    message: str
    errno: int | None = None
    protocol_code: int | None = None


def _error_packet(
    code: int,
    fatal: bool,
    request_id: int,
    message: str,
) -> bytes:
    encoded = message.encode("ascii")
    payload = _ERROR_PREFIX.pack(
        code,
        int(fatal),
        len(encoded),
    ) + encoded
    return Frame(FrameType.ERROR, request_id, payload).to_bytes()


_SLOW_CONSUMER_PACKET = _error_packet(
    SLOW_CONSUMER,
    True,
    0,
    "SLOW_CONSUMER",
)


class Connection:
    def __init__(
        self,
        sock: socket.socket,
        backend: Backend,
        *,
        max_payload: int = MAX_PAYLOAD,
        initial_input_capacity: int = INITIAL_INPUT_CAPACITY,
        low_watermark: int = LOW_WATERMARK,
        soft_limit: int = SOFT_LIMIT,
        hard_limit: int = HARD_LIMIT,
    ) -> None:
        validate_max_payload(max_payload)

        for value in (
            initial_input_capacity,
            low_watermark,
            soft_limit,
            hard_limit,
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise TypeError(
                    "capacities and watermarks must be integers"
                )

        if initial_input_capacity < 1:
            raise ValueError("initial_input_capacity must be positive")

        if not 0 < low_watermark < soft_limit < hard_limit:
            raise ValueError(
                "require 0 < low_watermark < soft_limit < hard_limit"
            )

        sock.setblocking(False)
        fd = sock.fileno()
        if fd < 0:
            raise ValueError("socket is closed")

        self.sock = sock
        self.fd = fd
        self._backend = backend
        self._state = ConnectionState.OPEN
        self._mask = READ
        self._registered = False
        self._backpressured = False

        self._low_watermark = low_watermark
        self._soft_limit = soft_limit
        self._hard_limit = hard_limit

        self._max_input = HEADER_SIZE + max_payload
        self._initial_input_capacity = min(
            initial_input_capacity,
            self._max_input,
        )
        self._input_capacity = self._initial_input_capacity
        self._inbound = bytearray()
        self._read_offset = 0

        self._outbound: deque[memoryview] = deque()
        self._queued_bytes = 0

        self._failure: ConnectionFailure | None = None
        self._errors: deque[ProtocolError] = deque(maxlen=64)
        self._decoder: FrameDecoder | None = FrameDecoder(max_payload)

        # M1 accepts buffers despite its bytes-only public annotation.
        self._feed: Callable[[memoryview], list[Frame]] | None = cast(
            Callable[[memoryview], list[Frame]],
            self._decoder.feed,
        )

        try:
            backend.register(fd, READ, self)
            self._registered = True
        except BaseException:
            self.close()
            raise

    @property
    def state(self) -> ConnectionState:
        return self._state

    @property
    def mask(self) -> int:
        return self._mask

    @property
    def queued_bytes(self) -> int:
        return self._queued_bytes

    @property
    def read_paused(self) -> bool:
        return self._backpressured

    @property
    def failure(self) -> ConnectionFailure | None:
        return self._failure

    @property
    def decoder(self) -> FrameDecoder | None:
        return self._decoder

    @property
    def input_read_offset(self) -> int:
        return self._read_offset

    @property
    def input_capacity(self) -> int:
        return self._input_capacity

    @property
    def buffered_input_bytes(self) -> int:
        decoder_bytes = (
            0
            if self._decoder is None
            else self._decoder.buffered_bytes
        )
        return (
            len(self._inbound)
            - self._read_offset
            + decoder_bytes
        )

    def fileno(self) -> int:
        if self._state == ConnectionState.CLOSED:
            return -1
        return self.fd

    def drain_errors(self) -> list[ProtocolError]:
        errors = list(self._errors)
        self._errors.clear()
        return errors

    def _record_failure(self, failure: ConnectionFailure) -> None:
        if self._failure is None:
            self._failure = failure

    def _network_failure(
        self,
        operation: str,
        error: OSError,
    ) -> None:
        self._record_failure(
            ConnectionFailure(
                FailureKind.NETWORK,
                operation,
                str(error),
                errno=error.errno,
            )
        )
        self.close()

    def _sync_interest(self) -> None:
        if self._state == ConnectionState.CLOSED:
            return

        mask = 0
        if (
            self._state == ConnectionState.OPEN
            and not self._backpressured
        ):
            mask |= READ

        if self._outbound:
            mask |= WRITE

        if mask == 0:
            self.close()
        elif mask != self._mask:
            try:
                self._backend.modify(self.fd, mask, self)
            except (OSError, KeyError, RuntimeError) as error:
                self._record_failure(
                    ConnectionFailure(
                        FailureKind.BACKEND,
                        "modify",
                        str(error),
                        errno=(
                            error.errno
                            if isinstance(error, OSError)
                            else None
                        ),
                    )
                )
                self.close()
                return

            self._mask = mask

    @staticmethod
    def _output_view(data: OutputBuffer) -> memoryview:
        if isinstance(data, bytes):
            return memoryview(data)

        if not isinstance(data, memoryview):
            raise TypeError(
                "output must be bytes or a view backed by bytes"
            )

        if (
            not data.c_contiguous
            or not data.readonly
            or not isinstance(data.obj, bytes)
        ):
            raise TypeError(
                "output views must be contiguous and backed by bytes"
            )

        view = memoryview(data)
        if view.ndim == 1 and view.format == "B":
            return view

        try:
            return view.cast("B")
        finally:
            view.release()

    def queue_bytes(self, data: OutputBuffer) -> bool:
        """Queue immutable output; reject input after draining begins."""
        if self._state != ConnectionState.OPEN:
            return False

        view = self._output_view(data)
        if not view:
            view.release()
            return True

        if len(view) > self._hard_limit - self._queued_bytes:
            view.release()
            self._slow_consumer()
            return False

        self._outbound.append(view)
        self._queued_bytes += len(view)

        if self._queued_bytes >= self._soft_limit:
            self._backpressured = True

        self._sync_interest()
        return self._state != ConnectionState.CLOSED

    def queue_frame(self, frame: Frame) -> bool:
        return self.queue_bytes(frame.to_bytes())

    def _flush_chunks(
        self,
        budget: int,
        attempts: int,
    ) -> tuple[int, int]:
        sent = 0
        used = 0

        while (
            self._outbound
            and sent < budget
            and used < attempts
        ):
            used += 1
            head = self._outbound[0]

            try:
                with head[:min(len(head), budget - sent)] as buf:
                    count = self.sock.send(buf)
            except OSError as error:
                if error.errno == errno.EINTR:
                    continue
                if error.errno in _WOULD_BLOCK:
                    break

                self._network_failure("send", error)
                return sent, used

            if count == 0:
                self._network_failure(
                    "send",
                    OSError(errno.EPIPE, "send returned zero"),
                )
                return sent, used

            sent += count
            self._queued_bytes -= count

            if count == len(head):
                self._outbound.popleft().release()
            else:
                self._outbound[0] = head[count:]
                head.release()

        return sent, used

    def write_ready(self) -> int:
        if self._state == ConnectionState.CLOSED:
            return 0

        sent, _used = self._flush_chunks(
            WRITE_BUDGET,
            IO_OPERATION_BUDGET,
        )

        if self._state != ConnectionState.CLOSED:
            if (
                self._backpressured
                and self._queued_bytes < self._low_watermark
            ):
                self._backpressured = False

            self._sync_interest()

        return sent

    def _slow_consumer(self) -> None:
        self._record_failure(
            ConnectionFailure(
                FailureKind.SLOW_CONSUMER,
                "queue",
                "outbound hard limit exceeded",
                protocol_code=SLOW_CONSUMER,
            )
        )
        self._state = ConnectionState.DRAINING

        sent = 0
        used = 0

        try:
            if (
                len(_SLOW_CONSUMER_PACKET)
                > self._hard_limit - self._queued_bytes
            ):
                sent, used = self._flush_chunks(
                    WRITE_BUDGET,
                    IO_OPERATION_BUDGET,
                )

            if self._state == ConnectionState.CLOSED:
                return

            # Preserve frame alignment, including a partially sent head.
            if (
                len(_SLOW_CONSUMER_PACKET)
                <= self._hard_limit - self._queued_bytes
            ):
                self._outbound.append(
                    memoryview(_SLOW_CONSUMER_PACKET)
                )
                self._queued_bytes += len(_SLOW_CONSUMER_PACKET)

            self._flush_chunks(
                WRITE_BUDGET - sent,
                IO_OPERATION_BUDGET - used,
            )
        finally:
            self.close()

    def _compact_input(self) -> None:
        if self._read_offset == len(self._inbound):
            self._inbound = bytearray()
            self._read_offset = 0
            self._input_capacity = self._initial_input_capacity

        elif self._read_offset > self._input_capacity // 2:
            remaining = len(self._inbound) - self._read_offset

            with memoryview(self._inbound) as buf:
                with buf[self._read_offset:] as tail:
                    buf[:remaining] = tail

            # Resizing happens only after every temporary view is released.
            del self._inbound[remaining:]
            self._read_offset = 0

    def _append_input(self, data: memoryview) -> None:
        self._compact_input()

        needed = len(self._inbound) + len(data)
        if needed > self._max_input:
            raise BufferError("inbound staging limit exceeded")

        while self._input_capacity < needed:
            self._input_capacity = min(
                self._max_input,
                self._input_capacity * 2,
            )

        # Capacity follows actual input, never the peer's claimed length.
        self._inbound.extend(data)

    def _consume_input(self, count: int) -> None:
        if not (
            0 <= count <= len(self._inbound) - self._read_offset
        ):
            raise ValueError("invalid inbound consumption count")

        self._read_offset += count
        self._compact_input()

    def _report_protocol_error(self, error: ProtocolError) -> None:
        self._errors.append(
            type(error)(
                str(error),
                request_id=error.request_id,
            )
        )

        if error.fatal:
            self._record_failure(
                ConnectionFailure(
                    FailureKind.PROTOCOL,
                    "decode",
                    str(error),
                    protocol_code=int(error.code),
                )
            )

        self.queue_bytes(
            _error_packet(
                int(error.code),
                error.fatal,
                error.request_id,
                error.code.name,
            )
        )

        if error.fatal:
            self.close_after_flush()

    def _decode_input(self) -> list[Frame]:
        decoder = self._decoder
        feed = self._feed
        if decoder is None or feed is None:
            return []

        count = len(self._inbound) - self._read_offset
        failure: ProtocolError | None = None

        try:
            with memoryview(self._inbound) as buf:
                with buf[self._read_offset:] as pending:
                    frames = feed(pending)
        except ProtocolError as error:
            frames = error.completed_frames
            failure = error

        self._consume_input(count)

        for error in decoder.drain_errors():
            if self._state == ConnectionState.CLOSED:
                break
            self._report_protocol_error(error)

        if (
            failure is not None
            and self._state != ConnectionState.CLOSED
        ):
            self._report_protocol_error(failure)

        return frames

    def feed_data(self, data: bytes | memoryview) -> list[Frame]:
        """Decode actual input using bounded staging windows."""
        if self._state != ConnectionState.OPEN:
            return []

        frames: list[Frame] = []

        with memoryview(data) as source:
            if (
                source.ndim != 1
                or source.format != "B"
                or not source.c_contiguous
            ):
                raise TypeError(
                    "input must be a contiguous byte buffer"
                )

            offset = 0
            while (
                offset < len(source)
                and self._state == ConnectionState.OPEN
            ):
                end = min(
                    len(source),
                    offset + self._max_input,
                )

                with source[offset:end] as buf:
                    self._append_input(buf)

                frames.extend(self._decode_input())
                offset = end

        return frames

    def read_ready(self, scratch: bytearray) -> list[Frame]:
        if not isinstance(scratch, bytearray) or not scratch:
            raise ValueError(
                "scratch must be a nonempty bytearray"
            )

        frames: list[Frame] = []
        remaining = READ_BUDGET

        for _ in range(IO_OPERATION_BUDGET):
            if (
                self._state != ConnectionState.OPEN
                or self._backpressured
                or remaining == 0
            ):
                break

            try:
                count = self.sock.recv_into(
                    scratch,
                    min(len(scratch), remaining),
                )
            except OSError as error:
                if error.errno == errno.EINTR:
                    continue
                if error.errno in _WOULD_BLOCK:
                    break

                self._network_failure("recv_into", error)
                break

            if count == 0:
                self.close_after_flush()
                break

            remaining -= count

            with memoryview(scratch) as buf:
                with buf[:count] as received:
                    frames.extend(self.feed_data(received))

            if frames:
                # Let the owner queue replies before observing a later EOF.
                break

        return frames

    def close_after_flush(self) -> None:
        if self._state == ConnectionState.CLOSED:
            return

        self._state = ConnectionState.DRAINING
        self._inbound = bytearray()
        self._read_offset = 0
        self._input_capacity = self._initial_input_capacity
        self._decoder = None
        self._feed = None

        self._sync_interest()

    def handle_events(
        self,
        mask: int,
        scratch: bytearray,
    ) -> list[Frame]:
        """Handle one connection readiness entry from one poll pass."""
        if self._state == ConnectionState.CLOSED:
            return []

        if mask & (ERROR | HANGUP):
            try:
                code = self.sock.getsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_ERROR,
                )
            except OSError as error:
                self._network_failure("getsockopt", error)
                return []

            if code or mask & ERROR:
                self._network_failure(
                    "poll",
                    OSError(
                        code or errno.EIO,
                        "socket readiness failure",
                    ),
                )
            else:
                self.close()

            return []

        frames = (
            self.read_ready(scratch)
            if mask & (READ | PEER_CLOSED)
            else []
        )

        if (
            self._state != ConnectionState.CLOSED
            and mask & WRITE
        ):
            self.write_ready()

        return frames

    def close(self) -> None:
        if self._state == ConnectionState.CLOSED:
            return

        self._state = ConnectionState.CLOSED
        self._mask = 0
        self._backpressured = False

        try:
            if self._registered:
                self._registered = False
                try:
                    self._backend.unregister(self.fd)
                except (OSError, KeyError, RuntimeError) as error:
                    self._record_failure(
                        ConnectionFailure(
                            FailureKind.BACKEND,
                            "unregister",
                            str(error),
                            errno=(
                                error.errno
                                if isinstance(error, OSError)
                                else None
                            ),
                        )
                    )
        finally:
            try:
                self.sock.close()
            except OSError as error:
                # Retrying close after EINTR risks closing a reused fd.
                self._record_failure(
                    ConnectionFailure(
                        FailureKind.NETWORK,
                        "close",
                        str(error),
                        errno=error.errno,
                    )
                )
            finally:
                while self._outbound:
                    self._outbound.popleft().release()

                self._queued_bytes = 0
                self._inbound = bytearray()
                self._read_offset = 0
                self._input_capacity = self._initial_input_capacity
                self._decoder = None
                self._feed = None