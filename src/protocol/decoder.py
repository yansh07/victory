"""Bounded incremental framing, independent of sockets and payload grammars."""

from __future__ import annotations

from collections import deque
from typing import Literal, TypeAlias

from .frame import (
    HEADER_SIZE,
    HEADER_STRUCT,
    MAGIC,
    MAX_PAYLOAD,
    VERSION,
    BadMagic,
    Frame,
    FrameType,
    MalformedFrame,
    ProtocolError,
    UnknownType,
    UnsupportedVersion,
    validate_header,
    validate_max_payload,
)

DecoderState: TypeAlias = Literal["WAIT_HEADER", "WAIT_PAYLOAD", "FAILED"]

# Validate magic at 2 bytes, version at 3, flags at 5, reserved at 6,
# then length and type when the complete header is available.
_HEADER_STOPS = (2, 3, 5, 6, HEADER_SIZE)


class FrameDecoder:
    """Single-owner decoder; fatal failures permanently poison the instance.

    Unknown types are discarded without buffering. The latest 64 errors
    remain available through errors/drain_errors. unknown_type_count counts
    every occurrence. Session code must promote handshake errors to fatal.

    Payload syntax is checked separately by codec.decode_frame().
    """

    __slots__ = (
        "_max_payload",
        "_state",
        "_header",
        "_stage",
        "_payload",
        "_remaining",
        "_type",
        "_request_id",
        "_errors",
        "_unknown_type_count",
        "_failure",
    )

    def __init__(self, max_payload: int = MAX_PAYLOAD) -> None:
        validate_max_payload(max_payload)

        self._max_payload = max_payload
        self._state: DecoderState = "WAIT_HEADER"
        self._header = bytearray()
        self._stage = 0
        self._payload = bytearray()
        self._remaining = 0
        self._type: FrameType | None = None
        self._request_id = 0
        self._errors: deque[UnknownType] = deque(maxlen=64)
        self._unknown_type_count = 0

        # Retaining an exception traceback could retain the caller's input.
        self._failure: tuple[type[ProtocolError], str] | None = None

    @property
    def state(self) -> DecoderState:
        return self._state

    @property
    def buffered_bytes(self) -> int:
        return len(self._header) + len(self._payload)

    @property
    def unknown_type_count(self) -> int:
        return self._unknown_type_count

    @property
    def errors(self) -> list[UnknownType]:
        return list(self._errors)

    def drain_errors(self) -> list[UnknownType]:
        errors = list(self._errors)
        self._errors.clear()
        return errors

    def _accept_header(
        self,
        magic: int,
        version: int,
        frame_type: int,
        flags: int,
        reserved: int,
        request_id: int,
        length: int,
    ) -> None:
        try:
            self._type = validate_header(
                magic,
                version,
                frame_type,
                flags,
                reserved,
                request_id,
                length,
                max_payload=self._max_payload,
            )
        except UnknownType as error:
            self._type = None
            self._unknown_type_count += 1

            # Store a fresh, unraised exception without the caught traceback.
            self._errors.append(
                UnknownType(str(error), request_id=request_id)
            )

        self._request_id = request_id
        self._remaining = length
        self._state = "WAIT_PAYLOAD"

    def _finish(self, frames: list[Frame], payload: bytes) -> None:
        if self._type is not None:
            frames.append(Frame(self._type, self._request_id, payload))

        self._state = "WAIT_HEADER"
        self._type = None
        self._request_id = 0
        self._remaining = 0

        if self._payload:
            self._payload = bytearray()

    def feed(self, data: bytes) -> list[Frame]:
        """Emit complete frames; retain only validated, incomplete tails.

        Empty input is a no-op, not EOF. Partial frames remain buffered;
        the connection discards them on EOF.

        On fatal failure, the exception's completed_frames contains frames
        completed earlier in this call.
        """
        if self._failure is not None:
            error_type, message = self._failure
            raise error_type(f"decoder permanently failed: {message}")

        frames: list[Frame] = []
        view = memoryview(data)
        position = 0
        available = len(view)

        try:
            while position < available:
                if self._state == "WAIT_HEADER":
                    if (
                        not self._header
                        and available - position >= HEADER_SIZE
                    ):
                        # Parse directly from input; copy no header or payload.
                        self._accept_header(
                            *HEADER_STRUCT.unpack_from(view, position)
                        )
                        position += HEADER_SIZE
                    else:
                        target = _HEADER_STOPS[self._stage]
                        count = min(
                            target - len(self._header),
                            available - position,
                        )

                        self._header.extend(
                            view[position:position + count]
                        )
                        position += count

                        if len(self._header) < target:
                            break

                        if target == 2:
                            magic = (
                                self._header[0] << 8
                                | self._header[1]
                            )
                            if magic != MAGIC:
                                raise BadMagic("invalid magic")

                        elif target == 3:
                            if self._header[2] != VERSION:
                                raise UnsupportedVersion(
                                    "unsupported version: "
                                    f"{self._header[2]}"
                                )

                        elif target == 5:
                            if self._header[4] != 0:
                                raise MalformedFrame(
                                    "flags must be zero"
                                )

                        elif target == 6:
                            if self._header[5] != 0:
                                raise MalformedFrame(
                                    "reserved must be zero"
                                )

                        else:
                            self._accept_header(
                                *HEADER_STRUCT.unpack_from(self._header)
                            )
                            self._header = bytearray()
                            self._stage = 0

                        if target != HEADER_SIZE:
                            self._stage += 1
                            continue

                    if self._remaining == 0:
                        self._finish(frames, b"")
                        continue

                count = min(
                    self._remaining,
                    available - position,
                )
                end = position + count

                if self._type is None:
                    # Validated unknown frame: consume without copying.
                    self._remaining -= count
                    if self._remaining == 0:
                        self._finish(frames, b"")

                elif not self._payload and count == self._remaining:
                    # Complete payload: one ownership copy, no staging.
                    self._finish(
                        frames,
                        bytes(view[position:end]),
                    )

                else:
                    self._payload.extend(view[position:end])
                    self._remaining -= count

                    if self._remaining == 0:
                        self._finish(frames, bytes(self._payload))

                position = end

        except ProtocolError as error:
            self._failure = (type(error), str(error))
            self._state = "FAILED"
            self._header = bytearray()
            self._payload = bytearray()
            self._type = None
            self._request_id = 0
            self._remaining = 0
            error.completed_frames = frames
            raise

        finally:
            view.release()

        return frames