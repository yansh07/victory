from __future__ import annotations

from collections.abc import Sequence

import pytest

from victory.core.router import (
    DEDUPE_WINDOW,
    Action,
    AppendWalAction,
    CloseSessionAction,
    EnqueueClientBufferAction,
    Router,
)
from victory.core.session import CoreErrorCode, Session, SessionState
from victory.protocol.codec import (
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
    decode_frame,
    encode_payload,
    make_frame,
    pack_str,
)
from victory.protocol.decoder import FrameDecoder
from victory.protocol.frame import Frame, FrameType

_NODE_ID = 7
_TOKEN = "test-token"
_ROOM = "general"


@pytest.fixture
def router() -> Router:
    return Router(node_id=_NODE_ID, tokens=(_TOKEN,))


def _single_output(
    actions: Sequence[Action],
    *,
    session_id: int,
    frame_type: FrameType,
) -> EnqueueClientBufferAction:
    assert len(actions) == 1

    action = actions[0]
    assert isinstance(action, EnqueueClientBufferAction)
    assert action.session_id == session_id
    assert action.frame.type == frame_type
    assert action.packet == action.frame.to_bytes()
    assert FrameDecoder().feed(action.packet) == [action.frame]
    return action


def _single_append(actions: list[Action]) -> AppendWalAction:
    assert len(actions) == 1
    action = actions[0]
    assert isinstance(action, AppendWalAction)
    return action


def _outputs(
    actions: list[Action],
    frame_type: FrameType,
) -> list[EnqueueClientBufferAction]:
    return [
        action
        for action in actions
        if isinstance(action, EnqueueClientBufferAction)
        and action.frame.type == frame_type
    ]


def _assert_error(
    actions: list[Action],
    session: Session,
    *,
    code: int,
    request_id: int,
    fatal: bool,
) -> ErrorPayload:
    assert len(actions) == (2 if fatal else 1)

    output = actions[0]
    assert isinstance(output, EnqueueClientBufferAction)
    assert output.session_id == session.session_id
    assert output.frame.type == FrameType.ERROR
    assert output.frame.request_id == request_id
    assert output.packet == output.frame.to_bytes()
    assert FrameDecoder().feed(output.packet) == [output.frame]

    error = decode_frame(output.frame)
    assert isinstance(error, ErrorPayload)
    assert error.code == code
    assert error.fatal == int(fatal)
    assert error.message
    assert not any(
        isinstance(action, AppendWalAction)
        for action in actions
    )

    if fatal:
        close = actions[1]
        assert isinstance(close, CloseSessionAction)
        assert close.session_id == session.session_id
        assert close.after_flush is True
        assert session.state == SessionState.DRAINING
        assert session.closing
    else:
        assert not session.closing
        assert not any(
            isinstance(action, CloseSessionAction)
            for action in actions
        )

    return error


def _authenticate(
    router: Router,
    user: str = "alice",
) -> Session:
    session = router.open_session()
    assert session.state == SessionState.HANDSHAKE

    response = _single_output(
        router.route(
            session.session_id,
            make_frame(
                Hello(0, user, _TOKEN),
                request_id=1,
            ),
        ),
        session_id=session.session_id,
        frame_type=FrameType.HELLO_OK,
    )

    assert response.frame.request_id == 1
    assert decode_frame(response.frame) == HelloOk(
        session.session_id,
        _NODE_ID,
        10_000,
        65_536,
    )
    assert session.state == SessionState.ACTIVE
    assert session.user == user
    assert session.heartbeat_ms == 10_000
    assert not session.closing
    return session


@pytest.fixture
def authenticated_session(router: Router) -> Session:
    return _authenticate(router)


@pytest.mark.parametrize(
    "frame",
    [
        Frame(
            FrameType.JOIN,
            101,
            encode_payload(Join(_ROOM)),
        ),
        Frame(
            FrameType.MSG,
            102,
            encode_payload(Msg(_ROOM, 999, b"hello")),
        ),
    ],
    ids=[
        "join-before-hello",
        "message-before-hello",
    ],
)
def test_authentication_barrier(
    router: Router,
    frame: Frame,
) -> None:
    session = router.open_session()
    assert session.state == SessionState.HANDSHAKE
    assert session.user is None

    actions = router.route(session.session_id, frame)
    _assert_error(
        actions,
        session,
        code=int(CoreErrorCode.NOT_AUTHENTICATED),
        request_id=frame.request_id,
        fatal=True,
    )

    assert router.pending_count == 0
    assert router.rooms.last_sequence(_ROOM) == 0
    assert router.rooms.members(_ROOM) == frozenset()
    assert router.rooms.rooms_for(session.session_id) == frozenset()

    assert router.route(
        session.session_id,
        make_frame(
            Hello(0, "alice", _TOKEN),
            request_id=103,
        ),
    ) == []

    # The action consumer reports completion of the requested termination.
    router.disconnect(session.session_id)
    assert session.state == SessionState.CLOSED
    assert router.get_session(session.session_id) is None
    assert router.session_count == 0


@pytest.mark.parametrize(
    "completion_order",
    [
        [1, 2, 3, 4, 5],
        [5, 3, 4, 2, 1],
    ],
    ids=[
        "ordered-completions",
        "out-of-order-completions",
    ],
)
def test_room_sequence_sequencing_g2(
    router: Router,
    authenticated_session: Session,
    completion_order: list[int],
) -> None:
    session = authenticated_session
    router.rooms.join(session.session_id, _ROOM)

    assert router.rooms.members(_ROOM) == frozenset(
        {session.session_id}
    )

    records: list[AppendWalAction] = []

    # Keep five requests outstanding without introducing parallel execution.
    for sequence in range(1, 6):
        body = f"message-{sequence}".encode("utf-8")
        action = _single_append(
            router.route(
                session.session_id,
                make_frame(
                    Msg(_ROOM, sequence, body),
                    request_id=200 + sequence,
                ),
            )
        )

        assert action.record.seq == sequence
        assert action.record.room == _ROOM
        assert action.record.user == "alice"
        assert action.record.origin_node == _NODE_ID
        assert action.record.client_msg_id == sequence
        assert action.record.body == body
        assert action.record.request_id == 200 + sequence
        records.append(action)

    assert [
        action.record.seq
        for action in records
    ] == [1, 2, 3, 4, 5]
    assert router.rooms.last_sequence(_ROOM) == 5
    assert router.pending_count == 5
    assert router.cached_count("alice") == 0

    completed: list[Action] = []
    for index in completion_order:
        completed.extend(
            router.wal_committed(records[index - 1].commit_id)
        )

    acknowledgements = _outputs(completed, FrameType.ACK)
    deliveries = _outputs(completed, FrameType.DELIVER)

    assert len(completed) == 10
    assert len(acknowledgements) == len(deliveries) == 5

    for sequence, action in enumerate(
        acknowledgements,
        start=1,
    ):
        assert action.session_id == session.session_id
        assert action.frame.request_id == 200 + sequence
        assert decode_frame(action.frame) == Ack(
            FrameType.MSG,
            1,
            sequence,
        )
        assert action.packet == action.frame.to_bytes()

    for sequence, action in enumerate(deliveries, start=1):
        assert action.session_id == session.session_id
        assert action.frame.request_id == 0
        assert decode_frame(action.frame) == Deliver(
            _ROOM,
            _NODE_ID,
            sequence,
            "alice",
            sequence,
            f"message-{sequence}".encode("utf-8"),
        )
        assert action.packet == action.frame.to_bytes()

    assert router.pending_count == 0
    assert router.cached_count("alice") == 5
    assert router.rooms.last_sequence(_ROOM) == 5
    assert router.wal_committed(records[-1].commit_id) == []


def test_message_idempotency_and_deduplication_d2(
    router: Router,
    authenticated_session: Session,
) -> None:
    session = authenticated_session
    router.rooms.join(session.session_id, _ROOM)

    frame = make_frame(
        Msg(_ROOM, 999, b"original-message"),
        request_id=500,
    )
    append = _single_append(
        router.route(session.session_id, frame)
    )

    assert append.record.seq == 1
    assert router.cached_count("alice") == 0

    completed = router.wal_committed(append.commit_id)
    acknowledgements = _outputs(completed, FrameType.ACK)

    assert len(acknowledgements) == 1
    assert len(_outputs(completed, FrameType.DELIVER)) == 1

    acknowledgement = acknowledgements[0]
    assert decode_frame(acknowledgement.frame) == Ack(
        FrameType.MSG,
        1,
        1,
    )
    original_packet = acknowledgement.packet

    replayed = router.route(session.session_id, frame)
    assert replayed == [acknowledgement]

    replay = _single_output(
        replayed,
        session_id=session.session_id,
        frame_type=FrameType.ACK,
    )

    assert replay.packet == original_packet
    assert replay.frame == acknowledgement.frame
    assert not any(
        isinstance(action, AppendWalAction)
        for action in replayed
    )
    assert not _outputs(replayed, FrameType.DELIVER)
    assert router.rooms.last_sequence(_ROOM) == 1
    assert router.pending_count == 0
    assert router.cached_count("alice") == 1


def test_pending_duplicate_waits_for_original_durability(
    router: Router,
    authenticated_session: Session,
) -> None:
    session = authenticated_session
    router.rooms.join(session.session_id, _ROOM)

    frame = make_frame(
        Msg(_ROOM, 999, b"pending-message"),
        request_id=501,
    )
    append = _single_append(
        router.route(session.session_id, frame)
    )

    assert router.route(session.session_id, frame) == []
    assert router.pending_count == 1
    assert router.cached_count("alice") == 0
    assert router.rooms.last_sequence(_ROOM) == 1

    completed = router.wal_committed(append.commit_id)
    assert len(completed) == 2

    acknowledgement = _single_output(
        _outputs(completed, FrameType.ACK),
        session_id=session.session_id,
        frame_type=FrameType.ACK,
    )

    assert decode_frame(acknowledgement.frame) == Ack(
        FrameType.MSG,
        1,
        1,
    )
    assert len(_outputs(completed, FrameType.DELIVER)) == 1
    assert router.pending_count == 0


def test_retry_with_new_request_id_preserves_cached_ack_payload(
    router: Router,
    authenticated_session: Session,
) -> None:
    session = authenticated_session
    router.rooms.join(session.session_id, _ROOM)

    append = _single_append(
        router.route(
            session.session_id,
            make_frame(
                Msg(_ROOM, 999, b"hello"),
                request_id=502,
            ),
        )
    )
    original = _outputs(
        router.wal_committed(append.commit_id),
        FrameType.ACK,
    )[0]

    retried = _single_output(
        router.route(
            session.session_id,
            make_frame(
                Msg(_ROOM, 999, b"hello"),
                request_id=503,
            ),
        ),
        session_id=session.session_id,
        frame_type=FrameType.ACK,
    )

    assert retried.frame.request_id == 503
    assert retried.frame.payload == original.frame.payload
    assert decode_frame(retried.frame) == Ack(FrameType.MSG, 1, 1)
    assert router.rooms.last_sequence(_ROOM) == 1
    assert router.pending_count == 0


@pytest.mark.parametrize(
    ("frame_type", "payload"),
    [
        (FrameType.JOIN, b"\x00"),
        (FrameType.JOIN, b"\x00\x07gen"),
        (
            FrameType.JOIN,
            encode_payload(Join(_ROOM)) + b"trailing",
        ),
        (FrameType.JOIN, pack_str("bad room")),
        (FrameType.JOIN, b"\x00\x01\xff"),
        (FrameType.JOIN, b"\x00\x01\x00"),
        (
            FrameType.MSG,
            encode_payload(Msg(_ROOM, 1000, b"x"))[:-1],
        ),
        (
            FrameType.MSG,
            encode_payload(Msg(_ROOM, 1000, b"x")) + b"trailing",
        ),
        (
            FrameType.ACK,
            encode_payload(Ack(FrameType.JOIN, 0, 0)),
        ),
    ],
    ids=[
        "truncated-length-prefix",
        "truncated-room",
        "trailing-room-data",
        "invalid-room-characters",
        "invalid-utf8",
        "forbidden-nul",
        "truncated-message-body",
        "trailing-message-data",
        "server-only-command",
    ],
)
def test_invalid_command_formats_are_nonfatal_after_authentication(
    router: Router,
    authenticated_session: Session,
    frame_type: FrameType,
    payload: bytes,
) -> None:
    session = authenticated_session
    router.rooms.join(session.session_id, _ROOM)

    _assert_error(
        router.route(
            session.session_id,
            Frame(frame_type, 600, payload),
        ),
        session,
        code=5,
        request_id=600,
        fatal=False,
    )

    assert session.state == SessionState.ACTIVE
    assert session.user == "alice"
    assert router.rooms.members(_ROOM) == frozenset(
        {session.session_id}
    )
    assert router.rooms.last_sequence(_ROOM) == 0
    assert router.pending_count == 0

    response = _single_output(
        router.route(
            session.session_id,
            make_frame(Ping(77), request_id=601),
        ),
        session_id=session.session_id,
        frame_type=FrameType.PONG,
    )
    assert decode_frame(response.frame) == Pong(77)


def test_multiple_hello_frames_are_nonfatal(
    router: Router,
    authenticated_session: Session,
) -> None:
    session = authenticated_session

    for request_id in (700, 701, 702):
        _assert_error(
            router.route(
                session.session_id,
                make_frame(
                    Hello(60_000, "replacement", _TOKEN),
                    request_id=request_id,
                ),
            ),
            session,
            code=int(CoreErrorCode.ALREADY_HELLOED),
            request_id=request_id,
            fatal=False,
        )

        assert session.state == SessionState.ACTIVE
        assert session.user == "alice"
        assert session.heartbeat_ms == 10_000

    assert router.pending_count == 0
    assert router.rooms.rooms_for(session.session_id) == frozenset()


def test_clean_leave_and_room_sequence_retention(
    router: Router,
    authenticated_session: Session,
) -> None:
    session = authenticated_session

    joined = _single_output(
        router.route(
            session.session_id,
            make_frame(Join(_ROOM), request_id=800),
        ),
        session_id=session.session_id,
        frame_type=FrameType.ACK,
    )
    assert decode_frame(joined.frame) == Ack(FrameType.JOIN, 0, 0)

    append = _single_append(
        router.route(
            session.session_id,
            make_frame(
                Msg(_ROOM, 1, b"before-leave"),
                request_id=801,
            ),
        )
    )
    router.wal_committed(append.commit_id)

    left = _single_output(
        router.route(
            session.session_id,
            make_frame(Leave(_ROOM), request_id=802),
        ),
        session_id=session.session_id,
        frame_type=FrameType.ACK,
    )

    assert left.frame.request_id == 802
    assert decode_frame(left.frame) == Ack(FrameType.LEAVE, 0, 0)
    assert session.state == SessionState.ACTIVE
    assert not session.closing
    assert router.rooms.members(_ROOM) == frozenset()
    assert router.rooms.rooms_for(session.session_id) == frozenset()
    assert router.rooms.room_count == 0
    assert router.rooms.last_sequence(_ROOM) == 1

    _assert_error(
        router.route(
            session.session_id,
            make_frame(Leave(_ROOM), request_id=803),
        ),
        session,
        code=int(CoreErrorCode.NOT_IN_ROOM),
        request_id=803,
        fatal=False,
    )
    _assert_error(
        router.route(
            session.session_id,
            make_frame(
                Msg(_ROOM, 2, b"not-a-member"),
                request_id=804,
            ),
        ),
        session,
        code=int(CoreErrorCode.NOT_IN_ROOM),
        request_id=804,
        fatal=False,
    )

    assert router.rooms.last_sequence(_ROOM) == 1
    assert router.pending_count == 0

    router.route(
        session.session_id,
        make_frame(Join(_ROOM), request_id=805),
    )
    resumed = _single_append(
        router.route(
            session.session_id,
            make_frame(
                Msg(_ROOM, 2, b"after-rejoin"),
                request_id=806,
            ),
        )
    )

    assert resumed.record.seq == 2
    router.wal_committed(resumed.commit_id)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        encode_payload(Hello(0, "alice", _TOKEN)) + b"trailing",
    ],
    ids=[
        "truncated-hello",
        "trailing-hello-data",
    ],
)
def test_malformed_hello_is_fatal(
    router: Router,
    payload: bytes,
) -> None:
    session = router.open_session()

    _assert_error(
        router.route(
            session.session_id,
            Frame(FrameType.HELLO, 900, payload),
        ),
        session,
        code=5,
        request_id=900,
        fatal=True,
    )

    assert session.user is None
    assert router.pending_count == 0


def test_dedupe_window_evicts_oldest_without_refreshing_retries(
    router: Router,
    authenticated_session: Session,
) -> None:
    session = authenticated_session
    router.rooms.join(session.session_id, _ROOM)
    assert DEDUPE_WINDOW == 1024

    for client_msg_id in range(DEDUPE_WINDOW):
        append = _single_append(
            router.route(
                session.session_id,
                make_frame(
                    Msg(_ROOM, client_msg_id, b"x"),
                    request_id=1000 + client_msg_id,
                ),
            )
        )
        router.wal_committed(append.commit_id)

    assert router.cached_count("alice") == DEDUPE_WINDOW

    _single_output(
        router.route(
            session.session_id,
            make_frame(
                Msg(_ROOM, 0, b"x"),
                request_id=1000,
            ),
        ),
        session_id=session.session_id,
        frame_type=FrameType.ACK,
    )

    newest = _single_append(
        router.route(
            session.session_id,
            make_frame(
                Msg(_ROOM, DEDUPE_WINDOW, b"x"),
                request_id=2024,
            ),
        )
    )
    router.wal_committed(newest.commit_id)

    assert router.cached_count("alice") == DEDUPE_WINDOW
    assert router.rooms.last_sequence(_ROOM) == DEDUPE_WINDOW + 1

    oldest = _single_append(
        router.route(
            session.session_id,
            make_frame(
                Msg(_ROOM, 0, b"x"),
                request_id=1000,
            ),
        )
    )
    assert oldest.record.seq == DEDUPE_WINDOW + 2
    router.wal_committed(oldest.commit_id)


def test_deduplication_survives_reconnect_for_same_user(
    router: Router,
    authenticated_session: Session,
) -> None:
    original_session = authenticated_session
    router.rooms.join(original_session.session_id, _ROOM)

    frame = make_frame(
        Msg(_ROOM, 999, b"persistent-identity"),
        request_id=3000,
    )
    append = _single_append(
        router.route(original_session.session_id, frame)
    )
    original = _outputs(
        router.wal_committed(append.commit_id),
        FrameType.ACK,
    )[0]

    router.disconnect(original_session.session_id)
    replacement = _authenticate(router, "alice")
    router.rooms.join(replacement.session_id, _ROOM)

    replay = _single_output(
        router.route(replacement.session_id, frame),
        session_id=replacement.session_id,
        frame_type=FrameType.ACK,
    )

    assert replacement.session_id != original_session.session_id
    assert replay.packet == original.packet
    assert router.rooms.last_sequence(_ROOM) == 1
    assert router.pending_count == 0


def test_same_message_identifier_is_independent_for_different_users(
    router: Router,
    authenticated_session: Session,
) -> None:
    alice = authenticated_session
    bob = _authenticate(router, "bob")
    router.rooms.join(alice.session_id, _ROOM)
    router.rooms.join(bob.session_id, _ROOM)

    frame = make_frame(
        Msg(_ROOM, 999, b"same-identifier"),
        request_id=4000,
    )
    first = _single_append(router.route(alice.session_id, frame))
    second = _single_append(router.route(bob.session_id, frame))

    assert first.record.user == "alice"
    assert second.record.user == "bob"
    assert (first.record.seq, second.record.seq) == (1, 2)

    router.wal_committed(first.commit_id)
    router.wal_committed(second.commit_id)

    for session, sequence in ((alice, 1), (bob, 2)):
        replay = _single_output(
            router.route(session.session_id, frame),
            session_id=session.session_id,
            frame_type=FrameType.ACK,
        )
        assert decode_frame(replay.frame) == Ack(
            FrameType.MSG,
            1,
            sequence,
        )

    assert router.cached_count("alice") == 1
    assert router.cached_count("bob") == 1
    assert router.rooms.last_sequence(_ROOM) == 2
    assert router.pending_count == 0


def test_incorrect_authentication_token_is_fatal(
    router: Router,
) -> None:
    session = router.open_session()

    _assert_error(
        router.route(
            session.session_id,
            make_frame(
                Hello(0, "alice", "wrong-token"),
                request_id=5000,
            ),
        ),
        session,
        code=int(CoreErrorCode.AUTH_FAILED),
        request_id=5000,
        fatal=True,
    )

    assert session.user is None
    assert router.pending_count == 0


def test_room_sequence_counters_are_independent(
    router: Router,
    authenticated_session: Session,
) -> None:
    session = authenticated_session
    router.rooms.join(session.session_id, _ROOM)
    router.rooms.join(session.session_id, "other")

    expected = [
        (_ROOM, 1),
        ("other", 1),
        (_ROOM, 2),
        ("other", 2),
        (_ROOM, 3),
    ]
    appends: list[AppendWalAction] = []

    for client_msg_id, (room, sequence) in enumerate(
        expected,
        start=1,
    ):
        append = _single_append(
            router.route(
                session.session_id,
                make_frame(
                    Msg(room, client_msg_id, b"x"),
                    request_id=6000 + client_msg_id,
                ),
            )
        )

        assert append.record.room == room
        assert append.record.seq == sequence
        appends.append(append)

    deliveries: list[EnqueueClientBufferAction] = []
    for append in appends:
        deliveries.extend(
            _outputs(
                router.wal_committed(append.commit_id),
                FrameType.DELIVER,
            )
        )

    observed: list[tuple[str, int]] = []
    for action in deliveries:
        payload = decode_frame(action.frame)
        assert isinstance(payload, Deliver)
        observed.append((payload.room, payload.seq))

    assert observed == expected
    assert router.rooms.last_sequence(_ROOM) == 3
    assert router.rooms.last_sequence("other") == 2
    assert router.pending_count == 0