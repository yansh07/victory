"""Deterministic session state and application-level protocol failures."""

from __future__ import annotations

from enum import IntEnum

from ..protocol.codec import Hello, encode_payload
from ..protocol.frame import FrameType, MalformedPayload

UINT32_MAX = (1 << 32) - 1
UINT64_MAX = (1 << 64) - 1

MIN_HEARTBEAT_MS = 1000
MAX_HEARTBEAT_MS = 60_000


class SessionState(IntEnum):
    HANDSHAKE = 1
    ACTIVE = 2
    DRAINING = 3
    CLOSED = 4


class CoreErrorCode(IntEnum):
    NOT_AUTHENTICATED = 7
    AUTH_FAILED = 8
    ALREADY_HELLOED = 9
    NOT_IN_ROOM = 10
    ALREADY_IN_ROOM = 11
    ROOM_LIMIT = 12
    RATE_LIMITED = 13
    SLOW_CONSUMER = 14
    IDLE_TIMEOUT = 15
    HELLO_TIMEOUT = 16
    SERVER_SHUTTING_DOWN = 17
    INTERNAL = 18


_FATAL_CODES = frozenset(
    (
        CoreErrorCode.NOT_AUTHENTICATED,
        CoreErrorCode.AUTH_FAILED,
        CoreErrorCode.SLOW_CONSUMER,
        CoreErrorCode.IDLE_TIMEOUT,
        CoreErrorCode.HELLO_TIMEOUT,
        CoreErrorCode.INTERNAL,
    )
)

_CLIENT_COMMANDS = frozenset(
    (
        FrameType.JOIN,
        FrameType.LEAVE,
        FrameType.MSG,
        FrameType.PING,
        FrameType.PONG,
        FrameType.SHUTDOWN,
        FrameType.STATS,
    )
)

_DRAIN_COMMANDS = frozenset(
    (
        FrameType.PING,
        FrameType.PONG,
        FrameType.SHUTDOWN,
    )
)


class SessionError(Exception):
    """Application errors extending the framing layer's six wire codes."""

    def __init__(
        self,
        code: CoreErrorCode,
        message: str = "",
        *,
        request_id: int = 0,
    ) -> None:
        self.code = CoreErrorCode(code)
        self.fatal = self.code in _FATAL_CODES
        self.request_id = request_id
        super().__init__(message or self.code.name)

    def is_fatal(self, *, handshake: bool = False) -> bool:
        return self.fatal or handshake


def validate_uint(name: str, value: int, bits: int) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < (1 << bits)
    ):
        raise ValueError(
            f"{name} must be an unsigned {bits}-bit integer"
        )


class Session:
    __slots__ = (
        "_session_id",
        "_state",
        "_user",
        "_heartbeat_ms",
        "_closing",
    )

    def __init__(self, session_id: int) -> None:
        validate_uint("session_id", session_id, 64)
        if session_id == 0:
            raise ValueError("session_id must be nonzero")

        self._session_id = session_id
        self._state = SessionState.HANDSHAKE
        self._user: str | None = None
        self._heartbeat_ms = 0
        self._closing = False

    @property
    def session_id(self) -> int:
        return self._session_id

    @property
    def state(self) -> SessionState:
        return self._state

    @property
    def user(self) -> str | None:
        return self._user

    @property
    def heartbeat_ms(self) -> int:
        return self._heartbeat_ms

    @property
    def closing(self) -> bool:
        return self._closing

    def require_command(self, frame_type: FrameType | int) -> None:
        if self._state == SessionState.CLOSED or self._closing:
            raise SessionError(
                CoreErrorCode.NOT_AUTHENTICATED,
                "session is closing or closed",
            )

        if self._state == SessionState.HANDSHAKE:
            if frame_type != FrameType.HELLO:
                raise SessionError(
                    CoreErrorCode.NOT_AUTHENTICATED
                )
            return

        if frame_type == FrameType.HELLO:
            raise SessionError(CoreErrorCode.ALREADY_HELLOED)

        if self._state == SessionState.DRAINING:
            if frame_type not in _DRAIN_COMMANDS:
                raise SessionError(
                    CoreErrorCode.SERVER_SHUTTING_DOWN
                )
            return

        if frame_type not in _CLIENT_COMMANDS:
            raise MalformedPayload(
                "frame type is not a client command"
            )

    def activate(self, user: str, heartbeat_ms: int) -> None:
        if (
            self._state != SessionState.HANDSHAKE
            or self._closing
        ):
            raise SessionError(CoreErrorCode.ALREADY_HELLOED)

        validate_uint("heartbeat_ms", heartbeat_ms, 32)
        if not (
            MIN_HEARTBEAT_MS
            <= heartbeat_ms
            <= MAX_HEARTBEAT_MS
        ):
            raise ValueError(
                "negotiated heartbeat must be 1000 to 60000 ms"
            )

        encode_payload(Hello(heartbeat_ms, user, ""))

        self._user = user
        self._heartbeat_ms = heartbeat_ms
        self._state = SessionState.ACTIVE

    def begin_draining(self) -> None:
        if self._state == SessionState.CLOSED:
            return

        if self._state == SessionState.HANDSHAKE:
            raise SessionError(
                CoreErrorCode.NOT_AUTHENTICATED
            )

        self._state = SessionState.DRAINING

    def request_close(self) -> None:
        if self._state != SessionState.CLOSED:
            self._closing = True
            self._state = SessionState.DRAINING

    def close(self) -> None:
        self._closing = True
        self._state = SessionState.CLOSED