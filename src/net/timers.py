"""Single-owner timers using caller-supplied monotonic seconds.

Run due timers before dispatching newly received frames, then pass
get_next_timeout(now) to the readiness backend. Refresh activity only
after a complete, valid inbound frame.
"""

from __future__ import annotations

import heapq
import math
from collections import deque
from dataclasses import dataclass
from enum import IntEnum
from typing import Callable, TypeAlias

from ..core.router import (
    Action,
    CloseSessionAction,
    EnqueueClientBufferAction,
    Router,
)
from ..core.session import (
    MAX_HEARTBEAT_MS,
    MIN_HEARTBEAT_MS,
    CoreErrorCode,
    SessionState,
    validate_uint,
)
from ..protocol.codec import ErrorPayload, make_frame

HELLO_TIMEOUT_SECONDS = 5.0
IDLE_HEARTBEAT_MULTIPLIER = 3
DEFAULT_EVENT_BUDGET = 1024

TimerCallback: TypeAlias = Callable[[int, float], None]
ActionSink: TypeAlias = Callable[[list[Action]], None]


def _finite_time(name: str, value: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
    ):
        raise TypeError(f"{name} must be a real number")

    try:
        result = float(value)
    except OverflowError:
        raise ValueError(
            f"{name} is outside the finite float range"
        ) from None

    if not math.isfinite(result):
        raise ValueError(f"{name} must be finite")

    return result


def _deadline_after(start: float, delay: float) -> float:
    if delay < 0:
        raise ValueError("delay must be nonnegative")

    deadline = start + delay
    if not math.isfinite(deadline):
        raise ValueError(
            "deadline is outside the finite float range"
        )

    if delay > 0 and deadline - start < delay:
        # Avoid early expiry and zero-distance rearming after rounding.
        deadline = math.nextafter(deadline, math.inf)
        if not math.isfinite(deadline):
            raise ValueError(
                "no finite future deadline is representable"
            )

    return deadline


def _validate_timer_id(timer_id: int) -> None:
    if (
        isinstance(timer_id, bool)
        or not isinstance(timer_id, int)
        or timer_id < 1
    ):
        raise ValueError("timer_id must be a positive integer")


@dataclass(slots=True)
class _Activity:
    last_activity: float
    timeout: float


@dataclass(slots=True)
class _Timer:
    deadline: float
    callback: TimerCallback
    activity: _Activity | None = None


@dataclass(frozen=True, slots=True)
class TimerFailure:
    timer_id: int
    deadline: float
    fired_at: float
    exception_type: str
    message: str


class TimerHeap:
    """Order timers by (deadline, timer_id).

    Callbacks receive (timer_id, now). Activity refresh performs no heap
    operation. Due inactivity checks count against the dispatch budget.

    Callback exceptions are isolated and retained as bounded metadata.
    The loop owner must inspect drain_errors().
    """

    def __init__(self) -> None:
        self._heap: list[tuple[float, int]] = []
        self._timers: dict[int, _Timer] = {}
        self._cancelled: set[int] = set()
        self._last_timer_id = 0
        self._dispatching = False
        self._errors: deque[TimerFailure] = deque(maxlen=64)
        self._callback_failure_count = 0

    def __len__(self) -> int:
        return len(self._timers)

    @property
    def heap_size(self) -> int:
        return len(self._heap)

    @property
    def cancelled_count(self) -> int:
        return len(self._cancelled)

    @property
    def callback_failure_count(self) -> int:
        return self._callback_failure_count

    def is_pending(self, timer_id: int) -> bool:
        _validate_timer_id(timer_id)
        return timer_id in self._timers

    def deadline(self, timer_id: int) -> float | None:
        _validate_timer_id(timer_id)
        timer = self._timers.get(timer_id)
        return None if timer is None else timer.deadline

    def last_activity(self, timer_id: int) -> float | None:
        _validate_timer_id(timer_id)
        timer = self._timers.get(timer_id)

        if timer is None or timer.activity is None:
            return None

        return timer.activity.last_activity

    def _insert(
        self,
        deadline: float,
        callback: TimerCallback,
        activity: _Activity | None = None,
    ) -> int:
        if not callable(callback):
            raise TypeError("callback must be callable")

        self._last_timer_id += 1
        timer_id = self._last_timer_id
        self._timers[timer_id] = _Timer(
            deadline,
            callback,
            activity,
        )
        heapq.heappush(self._heap, (deadline, timer_id))
        return timer_id

    def schedule(
        self,
        deadline: float,
        callback: TimerCallback,
    ) -> int:
        deadline = _finite_time("deadline", deadline)
        return self._insert(deadline, callback)

    def schedule_after(
        self,
        now: float,
        delay: float,
        callback: TimerCallback,
    ) -> int:
        now = _finite_time("now", now)
        delay = _finite_time("delay", delay)

        return self._insert(
            _deadline_after(now, delay),
            callback,
        )

    def schedule_idle(
        self,
        last_activity: float,
        timeout: float,
        callback: TimerCallback,
    ) -> int:
        last_activity = _finite_time(
            "last_activity",
            last_activity,
        )
        timeout = _finite_time("timeout", timeout)

        if timeout <= 0:
            raise ValueError(
                "inactivity timeout must be positive"
            )

        deadline = _deadline_after(last_activity, timeout)
        return self._insert(
            deadline,
            callback,
            _Activity(last_activity, timeout),
        )

    def refresh(self, timer_id: int, now: float) -> bool:
        _validate_timer_id(timer_id)
        now = _finite_time("now", now)
        timer = self._timers.get(timer_id)

        if timer is None:
            return False

        activity = timer.activity
        if activity is None:
            raise ValueError(
                "only inactivity timers can be refreshed"
            )

        if now < activity.last_activity:
            raise ValueError(
                "activity timestamps must not move backwards"
            )

        # Validate representability without inserting or moving heap entries.
        _deadline_after(now, activity.timeout)
        activity.last_activity = now
        return True

    def _maybe_compact(self) -> None:
        if len(self._cancelled) > len(self._heap) // 2:
            self._heap = [
                (timer.deadline, timer_id)
                for timer_id, timer in self._timers.items()
            ]
            heapq.heapify(self._heap)
            self._cancelled.clear()

    def _prune_cancelled(self) -> None:
        while (
            self._heap
            and self._heap[0][1] not in self._timers
        ):
            _deadline, timer_id = heapq.heappop(self._heap)
            self._cancelled.discard(timer_id)

        self._maybe_compact()

    def cancel(self, timer_id: int) -> bool:
        _validate_timer_id(timer_id)
        timer = self._timers.pop(timer_id, None)

        if timer is None:
            return False

        # Cancellation releases callbacks immediately, including closures.
        self._cancelled.add(timer_id)
        self._maybe_compact()
        return True

    def clear(self) -> int:
        removed = len(self._timers)
        self._timers.clear()
        self._heap.clear()
        self._cancelled.clear()

        # Retired IDs remain retired so stale handles cannot cancel new work.
        return removed

    def get_next_timeout(self, now: float) -> float | None:
        now = _finite_time("now", now)
        self._prune_cancelled()

        if not self._heap:
            return None

        remaining = max(0.0, self._heap[0][0] - now)
        if not math.isfinite(remaining):
            raise ValueError(
                "remaining timeout is outside the finite float range"
            )

        return remaining

    def run_due(
        self,
        now: float,
        *,
        max_events: int = DEFAULT_EVENT_BUDGET,
    ) -> int:
        now = _finite_time("now", now)

        if (
            isinstance(max_events, bool)
            or not isinstance(max_events, int)
            or max_events < 1
        ):
            raise ValueError(
                "max_events must be a positive integer"
            )

        if self._dispatching:
            raise RuntimeError(
                "timer dispatch is not reentrant"
            )

        self._dispatching = True
        processed = 0
        fired = 0

        try:
            while processed < max_events:
                self._prune_cancelled()

                if (
                    not self._heap
                    or self._heap[0][0] > now
                ):
                    break

                deadline, timer_id = heapq.heappop(self._heap)
                timer = self._timers[timer_id]
                processed += 1

                activity = timer.activity
                if activity is not None:
                    elapsed = now - activity.last_activity
                    if elapsed < activity.timeout:
                        timer.deadline = _deadline_after(
                            activity.last_activity,
                            activity.timeout,
                        )
                        heapq.heappush(
                            self._heap,
                            (timer.deadline, timer_id),
                        )
                        continue

                # Remove before invoking callbacks so cancellation, clearing,
                # and scheduling from callbacks cannot reuse this timer.
                del self._timers[timer_id]
                fired += 1

                try:
                    timer.callback(timer_id, now)
                except Exception as error:
                    self._callback_failure_count += 1

                    try:
                        message = str(error)[:1024]
                    except Exception:
                        message = (
                            "exception message could not be formatted"
                        )

                    self._errors.append(
                        TimerFailure(
                            timer_id,
                            deadline,
                            now,
                            type(error).__qualname__,
                            message,
                        )
                    )

            self._maybe_compact()
            return fired

        finally:
            self._dispatching = False

    def drain_errors(self) -> list[TimerFailure]:
        errors = list(self._errors)
        self._errors.clear()
        return errors


class TimeoutKind(IntEnum):
    HANDSHAKE = 1
    IDLE = 2


@dataclass(frozen=True, slots=True)
class SessionTimeout:
    session_id: int
    timer_id: int
    kind: TimeoutKind
    fired_at: float

    @property
    def code(self) -> CoreErrorCode:
        if self.kind == TimeoutKind.HANDSHAKE:
            return CoreErrorCode.HELLO_TIMEOUT
        return CoreErrorCode.IDLE_TIMEOUT

    @property
    def fatal(self) -> bool:
        return True


@dataclass(frozen=True, slots=True)
class _Watch:
    timer_id: int
    kind: TimeoutKind
    started_at: float
    deadline: float


class SessionTimers:
    """Map timer expiry to M4 session state and structured actions.

    Call track_handshake() immediately after Router.open_session().
    After successful HELLO authentication, call handshake_completed().
    Process due timers before routing newly received frames.

    Call note_activity() only for complete valid inbound frames, and
    remove() when disconnecting. on_actions executes on the loop owner.
    """

    def __init__(
        self,
        heap: TimerHeap,
        router: Router,
        on_actions: ActionSink,
    ) -> None:
        if not callable(on_actions):
            raise TypeError("on_actions must be callable")

        self._heap = heap
        self._router = router
        self._on_actions = on_actions
        self._watches: dict[int, _Watch] = {}
        self._by_timer: dict[int, int] = {}
        self._expirations: deque[SessionTimeout] = deque(
            maxlen=64
        )

    def __len__(self) -> int:
        return len(self._watches)

    @staticmethod
    def _validate_session_id(session_id: int) -> None:
        validate_uint("session_id", session_id, 64)
        if session_id == 0:
            raise ValueError("session_id must be nonzero")

    def track_handshake(
        self,
        session_id: int,
        now: float,
    ) -> int:
        self._validate_session_id(session_id)
        now = _finite_time("now", now)

        if session_id in self._watches:
            raise ValueError("session already has a timer")

        session = self._router.get_session(session_id)
        if (
            session is None
            or session.closing
            or session.state != SessionState.HANDSHAKE
        ):
            raise ValueError("session must be awaiting HELLO")

        deadline = _deadline_after(
            now,
            HELLO_TIMEOUT_SECONDS,
        )
        timer_id = self._heap.schedule(deadline, self._expire)

        self._watches[session_id] = _Watch(
            timer_id,
            TimeoutKind.HANDSHAKE,
            now,
            deadline,
        )
        self._by_timer[timer_id] = session_id
        return timer_id

    def handshake_completed(
        self,
        session_id: int,
        now: float,
    ) -> bool:
        self._validate_session_id(session_id)
        now = _finite_time("now", now)
        watch = self._watches.get(session_id)

        if watch is None:
            return False

        if watch.kind != TimeoutKind.HANDSHAKE:
            raise ValueError(
                "session handshake was already completed"
            )

        if now < watch.started_at:
            raise ValueError(
                "handshake completion predates acceptance"
            )

        if now >= watch.deadline:
            return False

        session = self._router.get_session(session_id)
        if (
            session is None
            or session.closing
            or session.state != SessionState.ACTIVE
        ):
            raise ValueError(
                "router must authenticate HELLO first"
            )

        heartbeat_ms = session.heartbeat_ms
        if not (
            MIN_HEARTBEAT_MS
            <= heartbeat_ms
            <= MAX_HEARTBEAT_MS
        ):
            raise ValueError(
                "negotiated heartbeat is outside the v1 range"
            )

        if not self._heap.is_pending(watch.timer_id):
            self.remove(session_id)
            return False

        timeout = (
            IDLE_HEARTBEAT_MULTIPLIER
            * heartbeat_ms
            / 1000.0
        )
        timer_id = self._heap.schedule_idle(
            now,
            timeout,
            self._expire,
        )

        self._heap.cancel(watch.timer_id)
        del self._by_timer[watch.timer_id]

        deadline = self._heap.deadline(timer_id)
        if deadline is None:
            raise RuntimeError(
                "new idle timer disappeared"
            )

        self._watches[session_id] = _Watch(
            timer_id,
            TimeoutKind.IDLE,
            now,
            deadline,
        )
        self._by_timer[timer_id] = session_id
        return True

    def note_activity(
        self,
        session_id: int,
        now: float,
    ) -> bool:
        self._validate_session_id(session_id)
        now = _finite_time("now", now)
        watch = self._watches.get(session_id)

        if watch is None or watch.kind != TimeoutKind.IDLE:
            return False

        session = self._router.get_session(session_id)
        if (
            session is None
            or session.closing
            or session.state == SessionState.CLOSED
        ):
            self.remove(session_id)
            return False

        if not self._heap.refresh(watch.timer_id, now):
            self.remove(session_id)
            return False

        return True

    def remove(self, session_id: int) -> bool:
        self._validate_session_id(session_id)
        watch = self._watches.pop(session_id, None)

        if watch is None:
            return False

        self._by_timer.pop(watch.timer_id, None)
        self._heap.cancel(watch.timer_id)
        return True

    def clear(self) -> int:
        removed = len(self._watches)

        for watch in self._watches.values():
            self._heap.cancel(watch.timer_id)

        self._watches.clear()
        self._by_timer.clear()
        return removed

    def _expire(self, timer_id: int, now: float) -> None:
        session_id = self._by_timer.pop(timer_id, None)
        if session_id is None:
            return

        watch = self._watches.get(session_id)
        if watch is None or watch.timer_id != timer_id:
            return

        del self._watches[session_id]
        session = self._router.get_session(session_id)

        if (
            session is None
            or session.closing
            or session.state == SessionState.CLOSED
        ):
            return

        event = SessionTimeout(
            session_id,
            timer_id,
            watch.kind,
            now,
        )
        self._expirations.append(event)

        frame = make_frame(
            ErrorPayload(
                int(event.code),
                1,
                event.code.name,
            )
        )

        session.request_close()
        self._router.rooms.disconnect(session_id)

        actions: list[Action] = [
            EnqueueClientBufferAction(
                session_id,
                frame,
                frame.to_bytes(),
            ),
            CloseSessionAction(
                session_id,
                after_flush=True,
            ),
        ]
        self._on_actions(actions)

    def drain_expirations(self) -> list[SessionTimeout]:
        events = list(self._expirations)
        self._expirations.clear()
        return events