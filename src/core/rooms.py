"""Connection-local membership and persistent per-room sequence counters."""

from __future__ import annotations

from ..protocol.codec import Join, encode_payload
from .session import (
    UINT64_MAX,
    CoreErrorCode,
    SessionError,
    validate_uint,
)


class Rooms:
    def __init__(self, max_rooms_per_session: int = 64) -> None:
        if (
            isinstance(max_rooms_per_session, bool)
            or not isinstance(max_rooms_per_session, int)
            or max_rooms_per_session < 1
        ):
            raise ValueError(
                "max_rooms_per_session must be positive"
            )

        self._limit = max_rooms_per_session
        self._members: dict[str, set[int]] = {}
        self._by_session: dict[int, set[str]] = {}
        self._sequences: dict[str, int] = {}

    @staticmethod
    def _validate_room(room: str) -> None:
        encode_payload(Join(room))

    @staticmethod
    def _validate_session_id(session_id: int) -> None:
        validate_uint("session_id", session_id, 64)
        if session_id == 0:
            raise ValueError("session_id must be nonzero")

    @property
    def room_count(self) -> int:
        return len(self._members)

    def members(self, room: str) -> frozenset[int]:
        return frozenset(self._members.get(room, ()))

    def rooms_for(self, session_id: int) -> frozenset[str]:
        return frozenset(self._by_session.get(session_id, ()))

    def is_member(self, session_id: int, room: str) -> bool:
        return session_id in self._members.get(room, ())

    def require_member(self, session_id: int, room: str) -> None:
        if not self.is_member(session_id, room):
            raise SessionError(CoreErrorCode.NOT_IN_ROOM)

    def join(self, session_id: int, room: str) -> None:
        self._validate_session_id(session_id)
        self._validate_room(room)

        current = self._by_session.get(session_id)
        if current is not None:
            if room in current:
                raise SessionError(
                    CoreErrorCode.ALREADY_IN_ROOM
                )
            if len(current) >= self._limit:
                raise SessionError(CoreErrorCode.ROOM_LIMIT)

        if current is None:
            current = set()
            self._by_session[session_id] = current

        current.add(room)
        self._members.setdefault(room, set()).add(session_id)

    def leave(self, session_id: int, room: str) -> None:
        self._validate_room(room)
        self.require_member(session_id, room)

        members = self._members[room]
        members.remove(session_id)
        if not members:
            del self._members[room]

        joined = self._by_session[session_id]
        joined.remove(room)
        if not joined:
            del self._by_session[session_id]

    def disconnect(self, session_id: int) -> list[str]:
        joined = self._by_session.pop(session_id, None)
        if joined is None:
            return []

        removed = sorted(joined)
        for room in removed:
            members = self._members[room]
            members.remove(session_id)
            if not members:
                del self._members[room]

        # Empty rooms retain their counters so later joins cannot reset G2.
        return removed

    def last_sequence(self, room: str) -> int:
        return self._sequences.get(room, 0)

    def next_sequence(self, room: str) -> int:
        self._validate_room(room)
        current = self.last_sequence(room)

        if current == UINT64_MAX:
            raise SessionError(
                CoreErrorCode.INTERNAL,
                "room sequence exhausted",
            )

        return current + 1

    def assign_sequence(self, room: str) -> int:
        sequence = self.next_sequence(room)
        self._sequences[room] = sequence
        return sequence

    def restore_sequence(self, room: str, sequence: int) -> None:
        validate_uint("sequence", sequence, 64)

        if sequence != self.next_sequence(room):
            raise ValueError(
                "recovered room sequence is not gap-free"
            )

        self._sequences[room] = sequence