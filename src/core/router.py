"""Pure command routing with explicit persistence and output intentions.

Execute AppendWalAction objects in returned order. Call wal_committed()
only after the corresponding record is fsynced. Call wal_failed() on a
write or fsync failure. Message ACKs and fanout remain behind that barrier.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterable
from dataclasses import dataclass, field
from hmac import compare_digest
from typing import TypeAlias

from ..protocol.codec import (
    Ack,
    Deliver,
    ErrorPayload,
    Hello,
    HelloOk,
    Join,
    Leave,
    Msg,
    Ping,
    Pong,
    Shutdown,
    Stats,
    StatsOk,
    decode_frame,
    make_frame,
    pack_str,
)
from ..protocol.frame import (
    MAX_PAYLOAD,
    Frame,
    FrameType,
    MalformedPayload,
    ProtocolError,
    validate_max_payload,
)
from .rooms import Rooms
from .session import (
    MAX_HEARTBEAT_MS,
    MIN_HEARTBEAT_MS,
    UINT64_MAX,
    CoreErrorCode,
    Session,
    SessionError,
    SessionState,
    validate_uint,
)

DEDUPE_WINDOW = 1024


@dataclass(frozen=True, slots=True)
class WalMessage:
    commit_id: int
    origin_node: int
    room: str
    seq: int
    user: str
    client_msg_id: int
    body: bytes
    request_id: int


@dataclass(frozen=True, slots=True)
class AppendWalAction:
    record: WalMessage

    @property
    def commit_id(self) -> int:
        return self.record.commit_id


@dataclass(frozen=True, slots=True)
class EnqueueClientBufferAction:
    session_id: int
    frame: Frame
    packet: bytes


@dataclass(frozen=True, slots=True)
class CloseSessionAction:
    session_id: int
    after_flush: bool = True


Action: TypeAlias = (
    AppendWalAction
    | EnqueueClientBufferAction
    | CloseSessionAction
)


@dataclass(frozen=True, slots=True)
class _Committed:
    ack: Frame
    packet: bytes


@dataclass(slots=True)
class _Pending:
    record: WalMessage
    ack: Frame
    ack_packet: bytes
    deliver: Frame
    deliver_packet: bytes
    waiters: dict[tuple[int, int], None] = field(
        default_factory=dict
    )
    durable: bool = False


class Router:
    def __init__(
        self,
        node_id: int,
        *,
        tokens: Iterable[str],
        default_heartbeat_ms: int = 10_000,
        max_payload: int = MAX_PAYLOAD,
        max_rooms_per_session: int = 64,
        max_sessions: int = 10_000,
        max_pending: int = 4096,
        max_pending_waiters: int = 64,
    ) -> None:
        validate_uint("node_id", node_id, 32)
        validate_max_payload(max_payload)
        validate_uint(
            "default_heartbeat_ms",
            default_heartbeat_ms,
            32,
        )

        if not (
            MIN_HEARTBEAT_MS
            <= default_heartbeat_ms
            <= MAX_HEARTBEAT_MS
        ):
            raise ValueError(
                "default heartbeat must be 1000 to 60000 ms"
            )

        for value in (
            max_sessions,
            max_pending,
            max_pending_waiters,
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 1
            ):
                raise ValueError(
                    "capacity limits must be positive integers"
                )

        if isinstance(tokens, str):
            raise TypeError(
                "tokens must be an iterable of complete token strings"
            )

        configured_tokens: list[bytes] = []
        for token in tokens:
            pack_str(token, max_length=256)
            configured_tokens.append(token.encode("utf-8"))

        if not configured_tokens:
            raise ValueError(
                "at least one authentication token is required"
            )

        self.node_id = node_id
        self.rooms = Rooms(max_rooms_per_session)
        self._tokens = tuple(configured_tokens)
        self._default_heartbeat_ms = default_heartbeat_ms
        self._max_payload = max_payload
        self._max_sessions = max_sessions
        self._max_pending = max_pending
        self._max_pending_waiters = max_pending_waiters

        self._sessions: dict[int, Session] = {}
        self._last_session_id = 0
        self._last_commit_id = 0
        self._last_finalized_id = 0
        self._live_started = False
        self._draining = False
        self._failed = False

        self._pending: OrderedDict[int, _Pending] = OrderedDict()
        self._pending_keys: dict[tuple[str, int], int] = {}
        self._pending_per_user: dict[str, int] = {}
        self._dedupe: dict[
            str,
            OrderedDict[int, _Committed],
        ] = {}

    @property
    def session_count(self) -> int:
        return len(self._sessions)

    @property
    def pending_count(self) -> int:
        return len(self._pending)

    @property
    def draining(self) -> bool:
        return self._draining

    @property
    def failed(self) -> bool:
        return self._failed

    def cached_count(self, user: str) -> int:
        return len(self._dedupe.get(user, ()))

    def get_session(self, session_id: int) -> Session | None:
        return self._sessions.get(session_id)

    def open_session(self) -> Session:
        if self._draining or self._failed:
            raise SessionError(
                CoreErrorCode.SERVER_SHUTTING_DOWN
            )

        if len(self._sessions) >= self._max_sessions:
            raise SessionError(
                CoreErrorCode.RATE_LIMITED,
                "session capacity reached",
            )

        if self._last_session_id == UINT64_MAX:
            raise SessionError(
                CoreErrorCode.INTERNAL,
                "session identifiers exhausted",
            )

        self._last_session_id += 1
        session = Session(self._last_session_id)
        self._sessions[session.session_id] = session
        self._live_started = True
        return session

    def disconnect(self, session_id: int) -> None:
        session = self._sessions.pop(session_id, None)
        if session is not None:
            self.rooms.disconnect(session_id)
            session.close()

    @staticmethod
    def _enqueue(
        session_id: int,
        frame: Frame,
    ) -> EnqueueClientBufferAction:
        return EnqueueClientBufferAction(
            session_id,
            frame,
            frame.to_bytes(),
        )

    @staticmethod
    def _safe_message(message: str) -> str:
        encoded = message.replace("\x00", "").encode(
            "utf-8",
            errors="replace",
        )
        return encoded[:256].decode(
            "utf-8",
            errors="ignore",
        )

    def _error_actions(
        self,
        session: Session,
        code: int,
        message: str,
        *,
        fatal: bool,
        request_id: int,
    ) -> list[Action]:
        fatal = fatal or session.state == SessionState.HANDSHAKE

        frame = make_frame(
            ErrorPayload(
                code,
                int(fatal),
                self._safe_message(message),
            ),
            request_id=request_id,
        )
        actions: list[Action] = [
            self._enqueue(session.session_id, frame)
        ]

        if fatal:
            session.request_close()
            self.rooms.disconnect(session.session_id)
            actions.append(
                CloseSessionAction(session.session_id)
            )

        return actions

    def protocol_error(
        self,
        session_id: int,
        error: ProtocolError,
    ) -> list[Action]:
        session = self._sessions.get(session_id)
        if (
            session is None
            or session.closing
            or session.state == SessionState.CLOSED
        ):
            return []

        return self._error_actions(
            session,
            int(error.code),
            str(error),
            fatal=error.fatal,
            request_id=error.request_id,
        )

    def _authenticate(self, token: str) -> bool:
        supplied = token.encode("utf-8")
        matched = False

        for configured in self._tokens:
            matched |= compare_digest(supplied, configured)

        return matched

    def route(
        self,
        session_id: int,
        frame: Frame,
    ) -> list[Action]:
        session = self._sessions.get(session_id)
        if (
            session is None
            or session.closing
            or session.state == SessionState.CLOSED
        ):
            return []

        try:
            session.require_command(frame.type)
            payload = decode_frame(frame)

            if isinstance(payload, Hello):
                if not self._authenticate(payload.token):
                    raise SessionError(
                        CoreErrorCode.AUTH_FAILED
                    )

                heartbeat = (
                    payload.heartbeat_ms
                    or self._default_heartbeat_ms
                )
                heartbeat = min(
                    MAX_HEARTBEAT_MS,
                    max(MIN_HEARTBEAT_MS, heartbeat),
                )

                session.activate(payload.user, heartbeat)
                reply = make_frame(
                    HelloOk(
                        session_id,
                        self.node_id,
                        heartbeat,
                        self._max_payload,
                    ),
                    request_id=frame.request_id,
                )
                return [self._enqueue(session_id, reply)]

            if isinstance(payload, Join):
                self.rooms.join(session_id, payload.room)
                reply = make_frame(
                    Ack(FrameType.JOIN, 0, 0),
                    request_id=frame.request_id,
                )
                return [self._enqueue(session_id, reply)]

            if isinstance(payload, Leave):
                self.rooms.leave(session_id, payload.room)
                reply = make_frame(
                    Ack(FrameType.LEAVE, 0, 0),
                    request_id=frame.request_id,
                )
                return [self._enqueue(session_id, reply)]

            if isinstance(payload, Msg):
                return self._message(
                    session,
                    frame.request_id,
                    payload,
                )

            if isinstance(payload, Ping):
                reply = make_frame(
                    Pong(payload.nonce),
                    request_id=frame.request_id,
                )
                return [self._enqueue(session_id, reply)]

            if isinstance(payload, Pong):
                return []

            if isinstance(payload, Shutdown):
                if payload.reason != 1:
                    raise MalformedPayload(
                        "client SHUTDOWN reason must be 1"
                    )

                session.request_close()
                self.rooms.disconnect(session_id)
                return [CloseSessionAction(session_id)]

            if isinstance(payload, Stats):
                text = (
                    f"sessions={self.session_count}\n"
                    f"rooms={self.rooms.room_count}\n"
                    f"pending_wal={self.pending_count}\n"
                )
                reply = make_frame(
                    StatsOk(text),
                    request_id=frame.request_id,
                )
                return [self._enqueue(session_id, reply)]

            raise MalformedPayload(
                "unsupported client command"
            )

        except (ProtocolError, SessionError) as error:
            return self._error_actions(
                session,
                int(error.code),
                str(error),
                fatal=error.fatal,
                request_id=frame.request_id,
            )

    @staticmethod
    def _replay_ack(
        session_id: int,
        request_id: int,
        ack: Frame,
        packet: bytes,
    ) -> EnqueueClientBufferAction:
        if request_id == ack.request_id:
            return EnqueueClientBufferAction(
                session_id,
                ack,
                packet,
            )

        # Reuse identical cached ACK bytes for the original request ID.
        # A new correlation ID requires a new header with the same ACK payload.
        reply = Frame(
            FrameType.ACK,
            request_id,
            ack.payload,
        )
        return EnqueueClientBufferAction(
            session_id,
            reply,
            reply.to_bytes(),
        )

    def _message(
        self,
        session: Session,
        request_id: int,
        message: Msg,
    ) -> list[Action]:
        self.rooms.require_member(
            session.session_id,
            message.room,
        )

        user = session.user
        if user is None:
            raise SessionError(
                CoreErrorCode.INTERNAL,
                "active session lacks identity",
            )

        cache = self._dedupe.get(user)
        committed = (
            None
            if cache is None
            else cache.get(message.client_msg_id)
        )

        if committed is not None:
            return [
                self._replay_ack(
                    session.session_id,
                    request_id,
                    committed.ack,
                    committed.packet,
                )
            ]

        key = (user, message.client_msg_id)
        pending_id = self._pending_keys.get(key)
        waiter = (session.session_id, request_id)

        if pending_id is not None:
            pending = self._pending[pending_id]

            if waiter not in pending.waiters:
                if (
                    len(pending.waiters)
                    >= self._max_pending_waiters
                ):
                    raise SessionError(
                        CoreErrorCode.RATE_LIMITED,
                        "retry waiter capacity reached",
                    )
                pending.waiters[waiter] = None

            # In-flight retries cannot receive a durability promise yet.
            return []

        if (
            len(self._pending) >= self._max_pending
            or self._pending_per_user.get(user, 0)
            >= DEDUPE_WINDOW
        ):
            raise SessionError(
                CoreErrorCode.RATE_LIMITED,
                "pending WAL capacity reached",
            )

        if self._last_commit_id == UINT64_MAX:
            raise SessionError(
                CoreErrorCode.INTERNAL,
                "commit identifiers exhausted",
            )

        sequence = self.rooms.next_sequence(message.room)
        commit_id = self._last_commit_id + 1

        ack = make_frame(
            Ack(FrameType.MSG, 1, sequence),
            request_id=request_id,
        )
        deliver = make_frame(
            Deliver(
                message.room,
                self.node_id,
                sequence,
                user,
                message.client_msg_id,
                message.body,
            )
        )
        record = WalMessage(
            commit_id,
            self.node_id,
            message.room,
            sequence,
            user,
            message.client_msg_id,
            message.body,
            request_id,
        )
        pending = _Pending(
            record,
            ack,
            ack.to_bytes(),
            deliver,
            deliver.to_bytes(),
            waiters={waiter: None},
        )

        # Rejections and encoding failures above cannot consume a sequence.
        self.rooms.assign_sequence(message.room)
        self._last_commit_id = commit_id
        self._pending[commit_id] = pending
        self._pending_keys[key] = commit_id
        self._pending_per_user[user] = (
            self._pending_per_user.get(user, 0) + 1
        )

        return [AppendWalAction(record)]

    def _cache(
        self,
        record: WalMessage,
        ack: Frame,
        packet: bytes,
    ) -> None:
        cache = self._dedupe.setdefault(
            record.user,
            OrderedDict(),
        )
        cache[record.client_msg_id] = _Committed(ack, packet)

        # Retry hits do not refresh the processed-message window.
        while len(cache) > DEDUPE_WINDOW:
            cache.popitem(last=False)

    def _can_receive(self, session_id: int) -> bool:
        session = self._sessions.get(session_id)
        return (
            session is not None
            and not session.closing
            and session.state
            in (SessionState.ACTIVE, SessionState.DRAINING)
        )

    def wal_committed(self, commit_id: int) -> list[Action]:
        """Release the ordered durable prefix after an fsync completion."""
        validate_uint("commit_id", commit_id, 64)

        if commit_id == 0 or commit_id > self._last_commit_id:
            raise ValueError("unknown commit identifier")

        if self._failed or commit_id <= self._last_finalized_id:
            return []

        self._pending[commit_id].durable = True
        actions: list[Action] = []

        while self._pending:
            first_id = next(iter(self._pending))
            pending = self._pending[first_id]
            if not pending.durable:
                break

            self._pending.pop(first_id)
            record = pending.record

            del self._pending_keys[
                (record.user, record.client_msg_id)
            ]

            remaining = self._pending_per_user[record.user] - 1
            if remaining:
                self._pending_per_user[record.user] = remaining
            else:
                del self._pending_per_user[record.user]

            self._cache(
                record,
                pending.ack,
                pending.ack_packet,
            )
            self._last_finalized_id = first_id

            for session_id, request_id in pending.waiters:
                if self._can_receive(session_id):
                    actions.append(
                        self._replay_ack(
                            session_id,
                            request_id,
                            pending.ack,
                            pending.ack_packet,
                        )
                    )

            for session_id in sorted(
                self.rooms.members(record.room)
            ):
                if self._can_receive(session_id):
                    actions.append(
                        EnqueueClientBufferAction(
                            session_id,
                            pending.deliver,
                            pending.deliver_packet,
                        )
                    )

        return actions

    def wal_failed(
        self,
        commit_id: int,
        message: str = "WAL write or fsync failed",
    ) -> list[Action]:
        validate_uint("commit_id", commit_id, 64)

        if self._failed:
            return []

        if commit_id not in self._pending:
            raise ValueError(
                "failure does not identify a pending WAL record"
            )

        self._failed = True
        self._draining = True
        self._pending.clear()
        self._pending_keys.clear()
        self._pending_per_user.clear()

        actions: list[Action] = []

        # An ambiguous persistence failure must not permit sequence reuse.
        # Recovery constructs a new Router and replays its durable prefix.
        for session_id in sorted(self._sessions):
            session = self._sessions[session_id]

            if (
                not session.closing
                and session.state != SessionState.CLOSED
            ):
                actions.extend(
                    self._error_actions(
                        session,
                        int(CoreErrorCode.INTERNAL),
                        message,
                        fatal=True,
                        request_id=0,
                    )
                )

        return actions

    def begin_shutdown(
        self,
        deadline_ms: int = 5000,
    ) -> list[Action]:
        validate_uint("deadline_ms", deadline_ms, 32)

        if self._draining:
            return []

        self._draining = True
        actions: list[Action] = []
        shutdown = make_frame(Shutdown(0, deadline_ms))
        packet = shutdown.to_bytes()

        for session_id in sorted(self._sessions):
            session = self._sessions[session_id]

            if (
                session.closing
                or session.state == SessionState.CLOSED
            ):
                continue

            if session.state == SessionState.HANDSHAKE:
                actions.extend(
                    self._error_actions(
                        session,
                        int(CoreErrorCode.SERVER_SHUTTING_DOWN),
                        "SERVER_SHUTTING_DOWN",
                        fatal=True,
                        request_id=0,
                    )
                )
            else:
                session.begin_draining()
                actions.append(
                    EnqueueClientBufferAction(
                        session_id,
                        shutdown,
                        packet,
                    )
                )

        return actions

    def restore_record(self, record: WalMessage) -> None:
        """Replay durable records in WAL order before live operation."""
        if (
            self._live_started
            or self._pending
            or self._failed
            or self._draining
        ):
            raise RuntimeError(
                "recovery is only allowed before live operation"
            )

        validate_uint("commit_id", record.commit_id, 64)
        validate_uint("request_id", record.request_id, 32)

        if record.commit_id != self._last_commit_id + 1:
            raise ValueError(
                "recovered commit identifiers are not contiguous"
            )

        if record.origin_node != self.node_id:
            raise ValueError(
                "recovered record belongs to a different node"
            )

        if record.seq != self.rooms.next_sequence(record.room):
            raise ValueError(
                "recovered room sequence is not gap-free"
            )

        make_frame(
            Deliver(
                record.room,
                record.origin_node,
                record.seq,
                record.user,
                record.client_msg_id,
                record.body,
            )
        )

        cache = self._dedupe.get(record.user)
        if (
            cache is not None
            and record.client_msg_id in cache
        ):
            raise ValueError(
                "duplicate idempotency key inside recovered window"
            )

        ack = make_frame(
            Ack(FrameType.MSG, 1, record.seq),
            request_id=record.request_id,
        )

        self.rooms.restore_sequence(
            record.room,
            record.seq,
        )
        self._cache(record, ack, ack.to_bytes())
        self._last_commit_id = record.commit_id
        self._last_finalized_id = record.commit_id