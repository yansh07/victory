from __future__ import annotations

import math
from dataclasses import dataclass
from random import Random

import pytest

from victory.core.router import (
    Action,
    CloseSessionAction,
    EnqueueClientBufferAction,
    Router,
)
from victory.core.session import (
    CoreErrorCode,
    Session,
    SessionState,
)
from victory.net.timers import (
    HELLO_TIMEOUT_SECONDS,
    IDLE_HEARTBEAT_MULTIPLIER,
    SessionTimers,
    TimeoutKind,
    TimerHeap,
)
from victory.protocol.codec import (
    ErrorPayload,
    Hello,
    HelloOk,
    Join,
    Ping,
    Pong,
    decode_frame,
    make_frame,
)
from victory.protocol.frame import FrameType

_TOKEN = "timer-test-token"


@dataclass(slots=True)
class _ManualClock:
    now: float = 0.0

    def advance(self, seconds: float) -> float:
        assert math.isfinite(seconds)
        assert seconds >= 0.0

        updated = self.now + seconds
        assert math.isfinite(updated)

        self.now = updated
        return self.now


@pytest.fixture
def clock() -> _ManualClock:
    return _ManualClock()


@pytest.fixture
def timer_heap() -> TimerHeap:
    return TimerHeap()


@pytest.fixture
def router() -> Router:
    return Router(node_id=7, tokens=(_TOKEN,))


@pytest.fixture
def timeout_actions() -> list[Action]:
    return []


@pytest.fixture
def session_timers(
    timer_heap: TimerHeap,
    router: Router,
    timeout_actions: list[Action],
) -> SessionTimers:
    return SessionTimers(
        timer_heap,
        router,
        timeout_actions.extend,
    )


def _assert_fatal_timeout(
    actions: list[Action],
    session: Session,
    code: CoreErrorCode,
) -> None:
    assert len(actions) == 2

    output = actions[0]
    assert isinstance(output, EnqueueClientBufferAction)
    assert output.session_id == session.session_id
    assert output.frame.type == FrameType.ERROR
    assert output.frame.request_id == 0
    assert output.packet == output.frame.to_bytes()
    assert decode_frame(output.frame) == ErrorPayload(
        int(code),
        1,
        code.name,
    )

    close = actions[1]
    assert isinstance(close, CloseSessionAction)
    assert close.session_id == session.session_id
    assert close.after_flush is True
    assert session.state == SessionState.DRAINING
    assert session.closing


def test_handshake_deadline_eviction(
    clock: _ManualClock,
    timer_heap: TimerHeap,
    router: Router,
    session_timers: SessionTimers,
    timeout_actions: list[Action],
) -> None:
    session = router.open_session()
    timer_id = session_timers.track_handshake(
        session.session_id,
        clock.now,
    )

    assert HELLO_TIMEOUT_SECONDS == 5.0
    assert session.state == SessionState.HANDSHAKE
    assert len(timer_heap) == len(session_timers) == 1
    assert timer_heap.deadline(timer_id) == 5.0
    assert timer_heap.get_next_timeout(clock.now) == 5.0
    assert timer_heap.run_due(clock.now) == 0
    assert timeout_actions == []

    clock.advance(5.1)

    assert math.isclose(
        clock.now,
        5.1,
        rel_tol=0.0,
        abs_tol=1e-12,
    )
    assert timer_heap.get_next_timeout(clock.now) == 0.0
    assert timer_heap.run_due(clock.now) == 1

    _assert_fatal_timeout(
        timeout_actions,
        session,
        CoreErrorCode.HELLO_TIMEOUT,
    )

    assert not timer_heap.is_pending(timer_id)
    assert len(timer_heap) == len(session_timers) == 0
    assert timer_heap.heap_size == 0
    assert timer_heap.get_next_timeout(clock.now) is None

    events = session_timers.drain_expirations()
    assert len(events) == 1
    assert events[0].session_id == session.session_id
    assert events[0].timer_id == timer_id
    assert events[0].kind == TimeoutKind.HANDSHAKE
    assert events[0].code == CoreErrorCode.HELLO_TIMEOUT
    assert events[0].fatal is True
    assert events[0].fired_at == clock.now
    assert session_timers.drain_expirations() == []

    clock.advance(100.0)

    assert timer_heap.run_due(clock.now) == 0
    assert len(timeout_actions) == 2
    assert timer_heap.drain_errors() == []

    router.disconnect(session.session_id)
    assert session.state == SessionState.CLOSED


@pytest.mark.parametrize(
    "heartbeat_ms",
    [1000, 10_000, 60_000],
)
def test_ping_keeps_connection_alive_with_lazy_rearm(
    clock: _ManualClock,
    timer_heap: TimerHeap,
    router: Router,
    session_timers: SessionTimers,
    timeout_actions: list[Action],
    heartbeat_ms: int,
) -> None:
    session = router.open_session()
    handshake_timer = session_timers.track_handshake(
        session.session_id,
        clock.now,
    )

    hello_actions = router.route(
        session.session_id,
        make_frame(
            Hello(heartbeat_ms, "alice", _TOKEN),
            request_id=1,
        ),
    )

    assert len(hello_actions) == 1
    hello_output = hello_actions[0]
    assert isinstance(hello_output, EnqueueClientBufferAction)
    assert decode_frame(hello_output.frame) == HelloOk(
        session.session_id,
        7,
        heartbeat_ms,
        65_536,
    )
    assert session_timers.handshake_completed(
        session.session_id,
        clock.now,
    )
    assert not timer_heap.is_pending(handshake_timer)

    router.route(
        session.session_id,
        make_frame(Join("general"), request_id=2),
    )

    timeout = (
        IDLE_HEARTBEAT_MULTIPLIER
        * session.heartbeat_ms
        / 1000.0
    )

    assert timeout == 3 * heartbeat_ms / 1000.0
    assert timer_heap.get_next_timeout(clock.now) == timeout

    pending_ids = [
        timer_id
        for _deadline, timer_id in timer_heap._heap
        if timer_heap.is_pending(timer_id)
    ]
    assert len(pending_ids) == 1

    idle_timer = pending_ids[0]
    original_deadline = timer_heap.deadline(idle_timer)
    assert original_deadline == timeout

    original_heap = timer_heap._heap.copy()
    original_heap_size = timer_heap.heap_size
    original_cancelled_count = timer_heap.cancelled_count

    clock.advance(timeout / 2)

    ping_actions = router.route(
        session.session_id,
        make_frame(Ping(123456), request_id=3),
    )

    assert len(ping_actions) == 1
    pong_output = ping_actions[0]
    assert isinstance(pong_output, EnqueueClientBufferAction)
    assert pong_output.frame.request_id == 3
    assert decode_frame(pong_output.frame) == Pong(123456)

    assert session_timers.note_activity(
        session.session_id,
        clock.now,
    )
    last_activity = clock.now

    # Activity must update only the register, leaving scheduled checks intact.
    assert timer_heap.last_activity(idle_timer) == last_activity
    assert timer_heap.deadline(idle_timer) == original_deadline
    assert timer_heap._heap == original_heap
    assert timer_heap.heap_size == original_heap_size
    assert timer_heap.cancelled_count == original_cancelled_count
    assert timeout_actions == []

    clock.advance(timeout / 2 + 0.25)

    assert clock.now > original_deadline
    assert timer_heap.get_next_timeout(clock.now) == 0.0
    assert timer_heap.run_due(clock.now) == 0

    rearmed_deadline = last_activity + timeout
    assert timer_heap.deadline(idle_timer) == rearmed_deadline

    residual = timer_heap.get_next_timeout(clock.now)
    assert residual is not None
    assert math.isclose(
        residual,
        rearmed_deadline - clock.now,
        rel_tol=0.0,
        abs_tol=1e-12,
    )
    assert timer_heap.is_pending(idle_timer)
    assert len(timer_heap) == len(session_timers) == 1
    assert timeout_actions == []
    assert session.state == SessionState.ACTIVE
    assert not session.closing
    assert session_timers.drain_expirations() == []

    clock.advance(rearmed_deadline - clock.now - 0.125)

    assert timer_heap.run_due(clock.now) == 0
    assert timer_heap.get_next_timeout(clock.now) == 0.125

    clock.advance(0.125)

    assert clock.now == rearmed_deadline
    assert timer_heap.run_due(clock.now) == 1

    _assert_fatal_timeout(
        timeout_actions,
        session,
        CoreErrorCode.IDLE_TIMEOUT,
    )

    assert router.rooms.members("general") == frozenset()
    assert len(timer_heap) == len(session_timers) == 0
    assert timer_heap.get_next_timeout(clock.now) is None

    events = session_timers.drain_expirations()
    assert len(events) == 1
    assert events[0].timer_id == idle_timer
    assert events[0].kind == TimeoutKind.IDLE
    assert events[0].code == CoreErrorCode.IDLE_TIMEOUT
    assert events[0].fired_at == rearmed_deadline
    assert timer_heap.drain_errors() == []


def test_high_scale_scrambled_timer_order_and_execution_lag(
    clock: _ManualClock,
    timer_heap: TimerHeap,
) -> None:
    timer_count = 1000
    deadlines = [
        (index + 1) / 8.0
        for index in range(timer_count)
    ]

    Random(0xCE57).shuffle(deadlines)
    assert deadlines != sorted(deadlines)

    expected: dict[int, float] = {}
    executed: list[tuple[float, int, float]] = []

    def record_expiration(timer_id: int, now: float) -> None:
        assert now == clock.now
        assert not timer_heap.is_pending(timer_id)
        executed.append((expected[timer_id], timer_id, now))

    for deadline in deadlines:
        timer_id = timer_heap.schedule(
            deadline,
            record_expiration,
        )
        assert timer_id not in expected
        expected[timer_id] = deadline

    assert (
        len(expected)
        == len(timer_heap)
        == timer_heap.heap_size
        == 1000
    )

    ordering = sorted(
        (deadline, timer_id)
        for timer_id, deadline in expected.items()
    )

    for index, (deadline, timer_id) in enumerate(ordering):
        timeout = timer_heap.get_next_timeout(clock.now)

        assert timeout is not None
        assert timeout > 0.0
        assert math.isclose(
            timeout,
            deadline - clock.now,
            rel_tol=0.0,
            abs_tol=1e-12,
        )

        clock.advance(timeout)

        assert clock.now == deadline
        assert timer_heap.get_next_timeout(clock.now) == 0.0
        assert timer_heap.run_due(
            clock.now,
            max_events=1,
        ) == 1

        assert len(executed) == index + 1
        assert executed[-1] == (deadline, timer_id, deadline)
        assert timer_heap.deadline(timer_id) is None
        assert len(timer_heap) == timer_count - index - 1

    # Virtual lag measures scheduler precision without OS scheduling noise.
    assert [
        (deadline, timer_id)
        for deadline, timer_id, _now in executed
    ] == ordering

    assert max(
        abs(now - deadline)
        for deadline, _timer_id, now in executed
    ) <= 1e-12

    assert len(executed) == 1000
    assert timer_heap.heap_size == timer_heap.cancelled_count == 0
    assert timer_heap.get_next_timeout(clock.now) is None
    assert timer_heap.run_due(clock.now) == 0
    assert timer_heap.callback_failure_count == 0
    assert timer_heap.drain_errors() == []


def test_equal_deadlines_are_ordered_by_timer_identifier(
    timer_heap: TimerHeap,
) -> None:
    executed: list[int] = []

    def record_expiration(timer_id: int, now: float) -> None:
        assert now == 5.0
        executed.append(timer_id)

    timer_ids = [
        timer_heap.schedule(5.0, record_expiration)
        for _ in range(20)
    ]

    assert timer_heap.run_due(5.0) == 20
    assert executed == timer_ids
    assert timer_heap.get_next_timeout(5.0) is None
    assert timer_heap.drain_errors() == []


def test_lazy_cancellation_compacts_and_never_fires_cancelled_timers(
    timer_heap: TimerHeap,
) -> None:
    executed: list[int] = []

    def record_expiration(timer_id: int, now: float) -> None:
        assert now == 2000.0
        executed.append(timer_id)

    timer_ids = [
        timer_heap.schedule(
            float(index + 1),
            record_expiration,
        )
        for index in range(1000)
    ]

    for timer_id in timer_ids[:600]:
        assert timer_heap.cancel(timer_id)
        assert not timer_heap.cancel(timer_id)

    assert len(timer_heap) == 400
    assert timer_heap.heap_size <= 2 * len(timer_heap)
    assert timer_heap.get_next_timeout(0.0) == 601.0
    assert timer_heap.run_due(2000.0) == 400
    assert executed == timer_ids[600:]
    assert timer_heap.heap_size == timer_heap.cancelled_count == 0
    assert timer_heap.get_next_timeout(2000.0) is None
    assert timer_heap.drain_errors() == []


def test_lazy_checks_count_against_dispatch_budget(
    timer_heap: TimerHeap,
) -> None:
    executed: list[int] = []

    def record_expiration(timer_id: int, now: float) -> None:
        assert now == 5.0
        executed.append(timer_id)

    timer_ids = [
        timer_heap.schedule_idle(
            0.0,
            3.0,
            record_expiration,
        )
        for _ in range(1000)
    ]

    for timer_id in timer_ids:
        assert timer_heap.refresh(timer_id, 2.0)

    assert timer_heap.run_due(3.0, max_events=100) == 0
    assert timer_heap.get_next_timeout(3.0) == 0.0
    assert executed == []

    assert timer_heap.run_due(3.0, max_events=900) == 0
    assert timer_heap.get_next_timeout(3.0) == 2.0
    assert len(timer_heap) == 1000
    assert timer_heap.heap_size == 1000

    assert timer_heap.run_due(5.0, max_events=1000) == 1000
    assert executed == timer_ids
    assert timer_heap.drain_errors() == []


def test_disconnect_cancels_only_the_sessions_owned_timer(
    clock: _ManualClock,
    timer_heap: TimerHeap,
    router: Router,
    session_timers: SessionTimers,
    timeout_actions: list[Action],
) -> None:
    session = router.open_session()
    owned_timer = session_timers.track_handshake(
        session.session_id,
        clock.now,
    )
    unrelated: list[int] = []

    def record_unrelated(timer_id: int, now: float) -> None:
        assert now == 10.0
        unrelated.append(timer_id)

    other_timer = timer_heap.schedule(
        10.0,
        record_unrelated,
    )

    assert session_timers.remove(session.session_id)
    assert not session_timers.remove(session.session_id)

    router.disconnect(session.session_id)

    assert session.state == SessionState.CLOSED
    assert not timer_heap.is_pending(owned_timer)
    assert timer_heap.is_pending(other_timer)
    assert len(timer_heap) == 1

    clock.advance(5.1)

    assert timer_heap.run_due(clock.now) == 0
    assert timeout_actions == []

    clock.advance(10.0 - clock.now)

    assert timer_heap.run_due(clock.now) == 1
    assert unrelated == [other_timer]
    assert timeout_actions == []
    assert timer_heap.get_next_timeout(clock.now) is None
    assert timer_heap.drain_errors() == []