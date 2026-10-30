"""Pure RESP2 encoding and bounded incremental decoding without I/O."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import TypeAlias

_CRLF = b"\r\n"
_INTEGER_MIN = -(1 << 63)
_INTEGER_MAX = (1 << 63) - 1
_FEED_CHUNK = 64 * 1024


@dataclass(frozen=True, slots=True)
class RespError:
    message: bytes


RespValue: TypeAlias = (
    bytes | int | None | RespError | list["RespValue"]
)
CommandArgument: TypeAlias = bytes | str | int


class RespProtocolError(ValueError):
    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.completed_values: list[RespValue] = []


class RespLimitError(RespProtocolError):
    """A declared or observed RESP resource limit was exceeded."""


def _line_bytes(value: bytes) -> bytes:
    if not isinstance(value, bytes):
        raise TypeError(
            "RESP strings must be immutable bytes"
        )
    if b"\r" in value or b"\n" in value:
        raise ValueError(
            "simple RESP values cannot contain CR or LF"
        )
    return value


def encode_bulk(value: bytes | None) -> bytes:
    if value is None:
        return b"$-1\r\n"

    if not isinstance(value, bytes):
        raise TypeError(
            "bulk strings must be immutable bytes"
        )

    return (
        b"$"
        + str(len(value)).encode("ascii")
        + _CRLF
        + value
        + _CRLF
    )


def encode_simple_string(value: bytes) -> bytes:
    return b"+" + _line_bytes(value) + _CRLF


def encode_error(value: bytes) -> bytes:
    return b"-" + _line_bytes(value) + _CRLF


def encode_integer(value: int) -> bytes:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not _INTEGER_MIN <= value <= _INTEGER_MAX
    ):
        raise ValueError(
            "RESP integers must be signed 64-bit integers"
        )
    return b":" + str(value).encode("ascii") + _CRLF


def encode(
    value: RespValue,
    *,
    max_depth: int = 32,
) -> bytes:
    if (
        isinstance(max_depth, bool)
        or not isinstance(max_depth, int)
        or max_depth < 1
    ):
        raise ValueError("max_depth must be positive")

    ancestors: set[int] = set()

    def encode_value(item: RespValue, depth: int) -> bytes:
        if item is None or isinstance(item, bytes):
            return encode_bulk(item)

        if isinstance(item, RespError):
            return encode_error(item.message)

        if isinstance(item, int):
            return encode_integer(item)

        if not isinstance(item, list):
            raise TypeError("unsupported RESP2 value")

        if depth >= max_depth:
            raise ValueError(
                "RESP array nesting limit exceeded"
            )

        identity = id(item)
        if identity in ancestors:
            raise ValueError(
                "cyclic RESP arrays are not supported"
            )

        ancestors.add(identity)
        try:
            prefix = (
                b"*"
                + str(len(item)).encode("ascii")
                + _CRLF
            )
            return prefix + b"".join(
                encode_value(child, depth + 1)
                for child in item
            )
        finally:
            ancestors.remove(identity)

    return encode_value(value, 0)


def encode_command(*arguments: CommandArgument) -> bytes:
    if not arguments:
        raise ValueError(
            "a Redis command must have at least one argument"
        )

    encoded: list[bytes] = []

    for argument in arguments:
        if isinstance(argument, bytes):
            value = argument
        elif isinstance(argument, str):
            value = argument.encode(
                "utf-8",
                errors="strict",
            )
        elif (
            isinstance(argument, int)
            and not isinstance(argument, bool)
        ):
            value = str(argument).encode("ascii")
        else:
            raise TypeError(
                "command arguments must be bytes, strings, or integers"
            )

        encoded.append(encode_bulk(value))

    return (
        b"*"
        + str(len(encoded)).encode("ascii")
        + _CRLF
        + b"".join(encoded)
    )


class DecoderState(IntEnum):
    LINE = 1
    BULK = 2
    FAILED = 3


@dataclass(slots=True)
class _Array:
    remaining: int
    values: list[RespValue] = field(default_factory=list)


class RespDecoder:
    def __init__(
        self,
        *,
        max_bulk: int = 1024 * 1024,
        max_array: int = 4096,
        max_depth: int = 32,
        max_line: int = 4096,
        max_message: int = 2 * 1024 * 1024,
        max_values: int = 8192,
    ) -> None:
        for value in (
            max_bulk,
            max_array,
            max_depth,
            max_line,
            max_message,
            max_values,
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 1
            ):
                raise ValueError(
                    "RESP limits must be positive integers"
                )

        if max_message < max_bulk + 2:
            raise ValueError(
                "max_message must accommodate a bulk body and CRLF"
            )

        self._max_bulk = max_bulk
        self._max_array = max_array
        self._max_depth = max_depth
        self._max_line = max_line
        self._max_message = max_message
        self._max_values = max_values
        self._max_buffer = max_message + max_line + 4

        self._buffer = bytearray()
        self._offset = 0
        self._scan = 0
        self._state = DecoderState.LINE
        self._bulk_length = 0
        self._arrays: list[_Array] = []
        self._message_bytes = 0
        self._message_values = 0
        self._failure = ""

    @property
    def state(self) -> DecoderState:
        return self._state

    @property
    def buffered_bytes(self) -> int:
        return len(self._buffer) - self._offset

    @property
    def pending_depth(self) -> int:
        return len(self._arrays)

    def reset(self) -> None:
        """Start a new stream, never resynchronize a damaged stream."""
        self._buffer = bytearray()
        self._offset = 0
        self._scan = 0
        self._state = DecoderState.LINE
        self._bulk_length = 0
        self._arrays.clear()
        self._message_bytes = 0
        self._message_values = 0
        self._failure = ""

    def _compact(self, *, force: bool = False) -> None:
        if self._offset == len(self._buffer):
            self._buffer = bytearray()
            self._offset = 0
            self._scan = 0
        elif self._offset and (
            force
            or self._offset > len(self._buffer) // 2
        ):
            consumed = self._offset
            del self._buffer[:consumed]
            self._offset = 0
            self._scan = max(0, self._scan - consumed)

    def _charge(self, size: int) -> None:
        self._message_bytes += size
        if self._message_bytes > self._max_message:
            raise RespLimitError(
                "RESP message exceeds its byte limit"
            )

    def _accept(
        self,
        value: RespValue,
        output: list[RespValue],
    ) -> None:
        while self._arrays:
            array = self._arrays[-1]
            array.values.append(value)
            array.remaining -= 1

            if array.remaining:
                return

            value = self._arrays.pop().values

        output.append(value)
        self._message_bytes = 0
        self._message_values = 0

    @staticmethod
    def _number(line: bytes, *, signed: bool) -> int:
        digits = line
        if signed and digits[:1] in (b"+", b"-"):
            digits = digits[1:]

        if not digits or any(
            character < 48 or character > 57
            for character in digits
        ):
            raise RespProtocolError(
                "invalid RESP decimal integer"
            )

        significant = digits.lstrip(b"0") or b"0"
        if len(significant) > 19:
            raise RespLimitError(
                "RESP integer exceeds signed 64-bit range"
            )

        value = int(significant)
        if signed and line[:1] == b"-":
            value = -value

        if not _INTEGER_MIN <= value <= _INTEGER_MAX:
            raise RespLimitError(
                "RESP integer exceeds signed 64-bit range"
            )

        return value

    def _line_end(self) -> int | None:
        position = max(
            self._scan,
            self._offset + 1,
        )

        while position < len(self._buffer):
            if (
                position - self._offset - 1
                > self._max_line
            ):
                raise RespLimitError(
                    "RESP line limit exceeded"
                )

            character = self._buffer[position]
            if (
                character not in (10, 13)
                and position - self._offset > self._max_line
            ):
                raise RespLimitError(
                    "RESP line limit exceeded"
                )

            if character == 10:
                raise RespProtocolError(
                    "bare LF in RESP line"
                )

            if character == 13:
                if position + 1 == len(self._buffer):
                    self._scan = position
                    return None

                if self._buffer[position + 1] != 10:
                    raise RespProtocolError(
                        "CR must be followed by LF"
                    )

                return position

            position += 1

        self._scan = position
        return None

    def _drain(self, output: list[RespValue]) -> None:
        while self._offset < len(self._buffer):
            if self._state == DecoderState.BULK:
                end = self._offset + self._bulk_length
                if end + 2 > len(self._buffer):
                    return

                if (
                    self._buffer[end] != 13
                    or self._buffer[end + 1] != 10
                ):
                    raise RespProtocolError(
                        "bulk string has no trailing CRLF"
                    )

                with memoryview(self._buffer) as buf:
                    value = bytes(buf[self._offset:end])

                self._charge(self._bulk_length + 2)
                self._offset = end + 2
                self._scan = self._offset
                self._state = DecoderState.LINE
                self._bulk_length = 0
                self._accept(value, output)
                continue

            marker = self._buffer[self._offset]
            if marker not in (43, 45, 58, 36, 42):
                raise RespProtocolError(
                    "unsupported RESP2 type marker"
                )

            end = self._line_end()
            if end is None:
                return

            with memoryview(self._buffer) as buf:
                line = bytes(
                    buf[self._offset + 1:end]
                )

            self._charge(end + 2 - self._offset)
            self._message_values += 1

            if self._message_values > self._max_values:
                raise RespLimitError(
                    "RESP value count exceeded"
                )

            self._offset = end + 2
            self._scan = self._offset

            if (
                marker == 42
                and len(self._arrays) >= self._max_depth
            ):
                raise RespLimitError(
                    "array nesting limit exceeded"
                )

            if marker == 43:
                self._accept(line, output)

            elif marker == 45:
                self._accept(RespError(line), output)

            elif marker == 58:
                self._accept(
                    self._number(line, signed=True),
                    output,
                )

            elif line == b"-1":
                self._accept(None, output)

            else:
                length = self._number(
                    line,
                    signed=False,
                )

                if marker == 36:
                    if length > self._max_bulk:
                        raise RespLimitError(
                            "bulk string limit exceeded"
                        )

                    if (
                        self._message_bytes + length + 2
                        > self._max_message
                    ):
                        raise RespLimitError(
                            "declared bulk exceeds message limit"
                        )

                    self._bulk_length = length
                    self._state = DecoderState.BULK

                elif length > self._max_array:
                    raise RespLimitError(
                        "array length limit exceeded"
                    )

                elif length == 0:
                    self._accept([], output)

                else:
                    self._arrays.append(_Array(length))

    def feed(
        self,
        data: bytes | bytearray | memoryview,
    ) -> list[RespValue]:
        if self._state == DecoderState.FAILED:
            raise RespProtocolError(
                f"decoder permanently failed: {self._failure}"
            )

        output: list[RespValue] = []

        try:
            with memoryview(data) as source:
                if (
                    source.ndim != 1
                    or source.format != "B"
                    or not source.c_contiguous
                ):
                    raise TypeError(
                        "RESP input must be a contiguous byte buffer"
                    )

                position = 0
                while position < len(source):
                    self._compact()
                    free = (
                        self._max_buffer
                        - len(self._buffer)
                    )

                    if free == 0:
                        self._compact(force=True)
                        free = (
                            self._max_buffer
                            - len(self._buffer)
                        )

                    if free == 0:
                        raise RespLimitError(
                            "RESP staging buffer limit exceeded"
                        )

                    count = min(
                        _FEED_CHUNK,
                        free,
                        len(source) - position,
                    )
                    self._buffer.extend(
                        source[position:position + count]
                    )
                    position += count
                    self._drain(output)

                self._drain(output)
                self._compact()

            return output

        except RespProtocolError as error:
            self._failure = str(error)
            self._state = DecoderState.FAILED
            self._buffer = bytearray()
            self._offset = 0
            self._scan = 0
            self._arrays.clear()
            error.completed_values = output
            raise