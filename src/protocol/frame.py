"""Wire constants, immutable raw frames, and M1 protocol failures."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from struct import Struct
from typing import ClassVar

MAGIC = 0xCE57
VERSION = 1
MAX_PAYLOAD = 65_536
HEADER_STRUCT = Struct("!HBBBBII")
HEADER_SIZE = HEADER_STRUCT.size


class FrameType(IntEnum):
    HELLO = 0x01
    JOIN = 0x02
    LEAVE = 0x03
    MSG = 0x04
    PING = 0x05
    PONG = 0x06
    ACK = 0x07
    ERROR = 0x08
    SHUTDOWN = 0x09
    DELIVER = 0x0A
    HELLO_OK = 0x0B
    STATS = 0x0C
    STATS_OK = 0x0D


class ErrorCode(IntEnum):
    BAD_MAGIC = 1
    UNSUPPORTED_VERSION = 2
    FRAME_TOO_LARGE = 3
    MALFORMED_FRAME = 4
    MALFORMED_PAYLOAD = 5
    UNKNOWN_TYPE = 6


class ProtocolError(Exception):
    """The session layer promotes every handshake error to fatal."""

    code: ClassVar[ErrorCode] = ErrorCode.MALFORMED_FRAME
    fatal: ClassVar[bool] = True

    def __init__(self, message: str = "", *, request_id: int = 0) -> None:
        super().__init__(message or self.code.name)
        self.request_id = request_id
        # Preserve valid frames preceding a fatal error in the same feed.
        self.completed_frames: list[Frame] = []

    def is_fatal(self, *, handshake: bool = False) -> bool:
        return self.fatal or handshake


class BadMagic(ProtocolError):
    code = ErrorCode.BAD_MAGIC


class UnsupportedVersion(ProtocolError):
    code = ErrorCode.UNSUPPORTED_VERSION


class FrameTooLarge(ProtocolError):
    code = ErrorCode.FRAME_TOO_LARGE


class MalformedFrame(ProtocolError):
    code = ErrorCode.MALFORMED_FRAME


class MalformedPayload(ProtocolError):
    code = ErrorCode.MALFORMED_PAYLOAD
    fatal = False


class UnknownType(ProtocolError):
    code = ErrorCode.UNKNOWN_TYPE
    fatal = False


def validate_max_payload(max_payload: int) -> None:
    if isinstance(max_payload, bool) or not isinstance(max_payload, int):
        raise TypeError("max_payload must be an integer")
    if not 0 <= max_payload <= MAX_PAYLOAD:
        raise ValueError(f"max_payload must be between 0 and {MAX_PAYLOAD}")


def validate_header(
    magic: int,
    version: int,
    frame_type: int,
    flags: int,
    reserved: int,
    request_id: int,
    length: int,
    *,
    max_payload: int = MAX_PAYLOAD,
) -> FrameType:
    """Validate an unpacked header in the mandated precedence order."""
    if magic != MAGIC:
        raise BadMagic(f"invalid magic: {magic:#06x}")

    if version != VERSION:
        raise UnsupportedVersion(f"unsupported version: {version}")

    if flags != 0 or reserved != 0:
        raise MalformedFrame("flags and reserved must both be zero")

    if length < 0 or length > max_payload:
        raise FrameTooLarge(
            f"payload length {length} exceeds limit {max_payload}"
        )

    try:
        known_type = FrameType(frame_type)
    except ValueError:
        raise UnknownType(
            f"unknown frame type: {frame_type:#04x}; skipping {length} bytes",
            request_id=request_id,
        ) from None

    return known_type


@dataclass(frozen=True, slots=True)
class Frame:
    """Own immutable payload bytes; codec.py checks payload grammar."""

    type: FrameType | int
    request_id: int = 0
    payload: bytes = b""
    magic: int = MAGIC
    version: int = VERSION
    flags: int = 0
    reserved: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.payload, bytes):
            raise TypeError("Frame.payload must be immutable bytes")

        for value in (
            self.magic,
            self.version,
            self.type,
            self.flags,
            self.reserved,
            self.request_id,
        ):
            if isinstance(value, bool) or not isinstance(value, int):
                raise MalformedFrame("header fields must be integers")

        known_type = validate_header(
            self.magic,
            self.version,
            self.type,
            self.flags,
            self.reserved,
            self.request_id,
            len(self.payload),
        )

        if not 0 <= self.request_id <= 0xFFFFFFFF:
            raise MalformedFrame(
                "request_id must be an unsigned 32-bit integer"
            )

        object.__setattr__(self, "type", known_type)

    @property
    def length(self) -> int:
        return len(self.payload)

    def to_bytes(self) -> bytes:
        return HEADER_STRUCT.pack(
            self.magic,
            self.version,
            self.type,
            self.flags,
            self.reserved,
            self.request_id,
            self.length,
        ) + self.payload