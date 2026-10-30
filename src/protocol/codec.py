"""Pure, strict payload codecs using unsigned network byte order."""

from __future__ import annotations

from dataclasses import dataclass
from struct import Struct
from typing import ClassVar, TypeAlias, cast

from .frame import (
    MAX_PAYLOAD,
    Frame,
    FrameType,
    MalformedPayload,
    UnknownType,
)

Buffer: TypeAlias = bytes | bytearray | memoryview

_U8 = Struct("!B")
_U16 = Struct("!H")
_U32 = Struct("!I")
_U64 = Struct("!Q")

_ROOM_CHARS = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"
)
_USER_CHARS = _ROOM_CHARS - {ord(":")}


def _view(data: Buffer) -> memoryview:
    view = data if isinstance(data, memoryview) else memoryview(data)
    if not view.c_contiguous:
        raise MalformedPayload("payload buffer must be contiguous")
    return (
        view
        if view.ndim == 1 and view.format == "B"
        else view.cast("B")
    )


def _end(view: memoryview, offset: int, size: int) -> int:
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise MalformedPayload("offset must be a nonnegative integer")

    end = offset + size
    if end > len(view):
        raise MalformedPayload(
            f"truncated payload at offset {offset}: need {size} bytes"
        )
    return end


def _pack_uint(value: int, layout: Struct) -> bytes:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < (1 << (layout.size * 8))
    ):
        raise MalformedPayload(
            f"expected unsigned {layout.size * 8}-bit integer"
        )
    return layout.pack(value)


def _unpack_uint(
    data: Buffer,
    offset: int,
    layout: Struct,
) -> tuple[int, int]:
    view = _view(data)
    end = _end(view, offset, layout.size)
    return cast(int, layout.unpack_from(view, offset)[0]), end


def pack_u8(value: int) -> bytes:
    return _pack_uint(value, _U8)


def pack_u16(value: int) -> bytes:
    return _pack_uint(value, _U16)


def pack_u32(value: int) -> bytes:
    return _pack_uint(value, _U32)


def pack_u64(value: int) -> bytes:
    return _pack_uint(value, _U64)


def unpack_u8(data: Buffer, offset: int = 0) -> tuple[int, int]:
    return _unpack_uint(data, offset, _U8)


def unpack_u16(data: Buffer, offset: int = 0) -> tuple[int, int]:
    return _unpack_uint(data, offset, _U16)


def unpack_u32(data: Buffer, offset: int = 0) -> tuple[int, int]:
    return _unpack_uint(data, offset, _U32)


def unpack_u64(data: Buffer, offset: int = 0) -> tuple[int, int]:
    return _unpack_uint(data, offset, _U64)


def pack_blob(value: Buffer, *, max_length: int = 0xFFFF) -> bytes:
    view = _view(value)
    if not 0 <= len(view) <= min(max_length, 0xFFFF):
        raise MalformedPayload("blob exceeds its byte-length limit")
    return _U16.pack(len(view)) + bytes(view)


def unpack_blob(
    data: Buffer,
    offset: int = 0,
    *,
    max_length: int = 0xFFFF,
) -> tuple[bytes, int]:
    view = _view(data)
    length, offset = unpack_u16(view, offset)

    if length > min(max_length, 0xFFFF):
        raise MalformedPayload("blob exceeds its byte-length limit")

    end = _end(view, offset, length)
    return bytes(view[offset:end]), end


def _utf8(value: str) -> bytes:
    if not isinstance(value, str):
        raise MalformedPayload("expected a string")
    try:
        return value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise MalformedPayload(
            "string contains an invalid Unicode surrogate"
        ) from None


def pack_str(value: str, *, max_length: int = 0xFFFF) -> bytes:
    # UTF-8 cannot use fewer bytes than the number of Python characters.
    if not isinstance(value, str) or len(value) > min(max_length, 0xFFFF):
        raise MalformedPayload("string exceeds its byte-length limit")

    encoded = _utf8(value)
    if b"\x00" in encoded:
        raise MalformedPayload("NUL is forbidden in a protocol string")

    return pack_blob(encoded, max_length=max_length)


def unpack_str(
    data: Buffer,
    offset: int = 0,
    *,
    max_length: int = 0xFFFF,
) -> tuple[str, int]:
    encoded, end = unpack_blob(data, offset, max_length=max_length)

    if b"\x00" in encoded:
        raise MalformedPayload("NUL is forbidden in a protocol string")

    try:
        return encoded.decode("utf-8", errors="strict"), end
    except UnicodeDecodeError:
        raise MalformedPayload("invalid UTF-8 in protocol string") from None


def require_consumed(data: Buffer, offset: int) -> None:
    view = _view(data)
    _end(view, offset, 0)
    if offset != len(view):
        raise MalformedPayload(
            f"{len(view) - offset} trailing payload bytes"
        )


def _name(value: str, *, user: bool = False) -> str:
    allowed = _USER_CHARS if user else _ROOM_CHARS

    if not isinstance(value, str) or not 1 <= len(value) <= 64:
        raise MalformedPayload(
            "room/user must contain 1 to 64 ASCII bytes"
        )

    if any(ord(character) not in allowed for character in value):
        raise MalformedPayload("invalid room/user character")

    return value


def _bit(value: int, field: str) -> int:
    if not isinstance(value, int) or value not in (0, 1):
        raise MalformedPayload(f"{field} must be 0 or 1")
    return int(value)


def _ack(acked_type: int, durable: int, seq: int) -> None:
    _bit(durable, "durable")
    if acked_type != FrameType.MSG and seq != 0:
        raise MalformedPayload("non-MSG ACK must have seq=0")


@dataclass(frozen=True, slots=True)
class Hello:
    TYPE: ClassVar[FrameType] = FrameType.HELLO
    heartbeat_ms: int
    user: str
    token: str


@dataclass(frozen=True, slots=True)
class HelloOk:
    TYPE: ClassVar[FrameType] = FrameType.HELLO_OK
    session_id: int
    node_id: int
    heartbeat_ms: int
    max_payload: int


@dataclass(frozen=True, slots=True)
class Join:
    TYPE: ClassVar[FrameType] = FrameType.JOIN
    room: str


@dataclass(frozen=True, slots=True)
class Leave:
    TYPE: ClassVar[FrameType] = FrameType.LEAVE
    room: str


@dataclass(frozen=True, slots=True)
class Msg:
    TYPE: ClassVar[FrameType] = FrameType.MSG
    room: str
    client_msg_id: int
    body: bytes


@dataclass(frozen=True, slots=True)
class Ping:
    TYPE: ClassVar[FrameType] = FrameType.PING
    nonce: int


@dataclass(frozen=True, slots=True)
class Pong:
    TYPE: ClassVar[FrameType] = FrameType.PONG
    nonce: int


@dataclass(frozen=True, slots=True)
class Ack:
    TYPE: ClassVar[FrameType] = FrameType.ACK
    acked_type: int
    durable: int
    seq: int


@dataclass(frozen=True, slots=True)
class ErrorPayload:
    TYPE: ClassVar[FrameType] = FrameType.ERROR
    code: int
    fatal: int
    message: str


@dataclass(frozen=True, slots=True)
class Shutdown:
    TYPE: ClassVar[FrameType] = FrameType.SHUTDOWN
    reason: int
    deadline_ms: int


@dataclass(frozen=True, slots=True)
class Deliver:
    TYPE: ClassVar[FrameType] = FrameType.DELIVER
    room: str
    origin_node: int
    seq: int
    sender: str
    client_msg_id: int
    body: bytes


@dataclass(frozen=True, slots=True)
class Stats:
    TYPE: ClassVar[FrameType] = FrameType.STATS


@dataclass(frozen=True, slots=True)
class StatsOk:
    TYPE: ClassVar[FrameType] = FrameType.STATS_OK
    text: str


Payload: TypeAlias = (
    Hello
    | HelloOk
    | Join
    | Leave
    | Msg
    | Ping
    | Pong
    | Ack
    | ErrorPayload
    | Shutdown
    | Deliver
    | Stats
    | StatsOk
)


def encode_payload(payload: Payload) -> bytes:
    match payload:
        case Hello(heartbeat_ms, user, token):
            encoded = (
                pack_u32(heartbeat_ms)
                + pack_str(_name(user, user=True), max_length=64)
                + pack_str(token, max_length=256)
            )

        case HelloOk(session_id, node_id, heartbeat_ms, max_payload):
            encoded = (
                pack_u64(session_id)
                + pack_u32(node_id)
                + pack_u32(heartbeat_ms)
                + pack_u32(max_payload)
            )

        case Join(room) | Leave(room):
            encoded = pack_str(_name(room), max_length=64)

        case Msg(room, client_msg_id, body):
            encoded = (
                pack_str(_name(room), max_length=64)
                + pack_u64(client_msg_id)
                + pack_blob(body, max_length=16_384)
            )

        case Ping(nonce) | Pong(nonce):
            encoded = pack_u64(nonce)

        case Ack(acked_type, durable, seq):
            _ack(acked_type, durable, seq)
            encoded = (
                pack_u8(acked_type)
                + pack_u8(_bit(durable, "durable"))
                + pack_u64(seq)
            )

        case ErrorPayload(code, fatal, message):
            encoded = (
                pack_u16(code)
                + pack_u8(_bit(fatal, "fatal"))
                + pack_str(message, max_length=256)
            )

        case Shutdown(reason, deadline_ms):
            encoded = (
                pack_u8(_bit(reason, "reason"))
                + pack_u32(deadline_ms)
            )

        case Deliver(room, origin_node, seq, sender, client_msg_id, body):
            encoded = (
                pack_str(_name(room), max_length=64)
                + pack_u32(origin_node)
                + pack_u64(seq)
                + pack_str(_name(sender, user=True), max_length=64)
                + pack_u64(client_msg_id)
                + pack_blob(body, max_length=16_384)
            )

        case Stats():
            encoded = b""

        case StatsOk(text):
            if len(text) > MAX_PAYLOAD:
                raise MalformedPayload(
                    "STATS_OK exceeds the frame payload limit"
                )
            encoded = _utf8(text)

        case _:
            raise TypeError("unsupported payload object")

    if len(encoded) > MAX_PAYLOAD:
        raise MalformedPayload(
            "encoded payload exceeds the frame payload limit"
        )

    return encoded


class _Reader:
    __slots__ = ("data", "offset")

    def __init__(self, data: Buffer) -> None:
        self.data = _view(data)
        self.offset = 0

        if len(self.data) > MAX_PAYLOAD:
            raise MalformedPayload(
                "payload exceeds the frame payload limit"
            )

    def u8(self) -> int:
        value, self.offset = unpack_u8(self.data, self.offset)
        return value

    def u16(self) -> int:
        value, self.offset = unpack_u16(self.data, self.offset)
        return value

    def u32(self) -> int:
        value, self.offset = unpack_u32(self.data, self.offset)
        return value

    def u64(self) -> int:
        value, self.offset = unpack_u64(self.data, self.offset)
        return value

    def string(self, max_length: int) -> str:
        value, self.offset = unpack_str(
            self.data,
            self.offset,
            max_length=max_length,
        )
        return value

    def name(self, *, user: bool = False) -> str:
        return _name(self.string(64), user=user)

    def blob(self, max_length: int) -> bytes:
        value, self.offset = unpack_blob(
            self.data,
            self.offset,
            max_length=max_length,
        )
        return value


def decode_payload(frame_type: FrameType | int, data: Buffer) -> Payload:
    try:
        kind = FrameType(frame_type)
    except ValueError:
        raise UnknownType(f"unknown frame type: {frame_type}") from None

    reader = _Reader(data)
    result: Payload

    match kind:
        case FrameType.HELLO:
            result = Hello(
                reader.u32(),
                reader.name(user=True),
                reader.string(256),
            )

        case FrameType.HELLO_OK:
            result = HelloOk(
                reader.u64(),
                reader.u32(),
                reader.u32(),
                reader.u32(),
            )

        case FrameType.JOIN:
            result = Join(reader.name())

        case FrameType.LEAVE:
            result = Leave(reader.name())

        case FrameType.MSG:
            result = Msg(
                reader.name(),
                reader.u64(),
                reader.blob(16_384),
            )

        case FrameType.PING:
            result = Ping(reader.u64())

        case FrameType.PONG:
            result = Pong(reader.u64())

        case FrameType.ACK:
            acked_type = reader.u8()
            durable = reader.u8()
            seq = reader.u64()
            _ack(acked_type, durable, seq)
            result = Ack(acked_type, durable, seq)

        case FrameType.ERROR:
            result = ErrorPayload(
                reader.u16(),
                _bit(reader.u8(), "fatal"),
                reader.string(256),
            )

        case FrameType.SHUTDOWN:
            result = Shutdown(
                _bit(reader.u8(), "reason"),
                reader.u32(),
            )

        case FrameType.DELIVER:
            result = Deliver(
                reader.name(),
                reader.u32(),
                reader.u64(),
                reader.name(user=True),
                reader.u64(),
                reader.blob(16_384),
            )

        case FrameType.STATS:
            result = Stats()

        case FrameType.STATS_OK:
            try:
                text = bytes(reader.data).decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                raise MalformedPayload(
                    "invalid UTF-8 in STATS_OK"
                ) from None
            reader.offset = len(reader.data)
            result = StatsOk(text)

        case _:
            raise UnknownType(f"unknown frame type: {frame_type}")

    require_consumed(reader.data, reader.offset)
    return result


def encode_frame(frame: Frame) -> bytes:
    return frame.to_bytes()


def make_frame(payload: Payload, *, request_id: int = 0) -> Frame:
    if isinstance(payload, Deliver) and request_id != 0:
        raise MalformedPayload("DELIVER must use request_id=0")

    return Frame(payload.TYPE, request_id, encode_payload(payload))


def decode_frame(frame: Frame) -> Payload:
    try:
        if frame.type == FrameType.DELIVER and frame.request_id != 0:
            raise MalformedPayload("DELIVER must use request_id=0")
        return decode_payload(frame.type, frame.payload)
    except MalformedPayload as error:
        error.request_id = frame.request_id
        raise