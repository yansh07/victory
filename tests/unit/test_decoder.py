from __future__ import annotations

import struct
from importlib import import_module

import pytest
from hypothesis import given, settings, strategies as st

FrameDecoder = import_module("victory.protocol.decoder").FrameDecoder
_frame_module = import_module("victory.protocol.frame")
ErrorCode = _frame_module.ErrorCode
Frame = _frame_module.Frame
FrameTooLarge = _frame_module.FrameTooLarge
FrameType = _frame_module.FrameType

# Independent wire definitions catch accidental changes in production constants.
_HEADER = struct.Struct("!HBBBBII")
_U16 = struct.Struct("!H")
_U32 = struct.Struct("!I")
_U64 = struct.Struct("!Q")

_MAGIC = 0xCE57
_VERSION = 1
_HEADER_SIZE = 14
_MAX_PAYLOAD = 65_536

_ROOM_NAMES = st.text(
    alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-",
    min_size=1,
    max_size=64,
)
_REQUEST_IDS = st.integers(min_value=0, max_value=0xFFFFFFFF)
_UNSIGNED_64 = st.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF)


def _pack_string(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return _U16.pack(len(encoded)) + encoded


def _pack_message(room: str, client_msg_id: int, body: bytes) -> bytes:
    return (
        _pack_string(room)
        + _U64.pack(client_msg_id)
        + _U16.pack(len(body))
        + body
    )


def _pack_frame(frame: Frame) -> bytes:
    return _HEADER.pack(
        _MAGIC,
        _VERSION,
        int(frame.type),
        0,
        0,
        frame.request_id,
        len(frame.payload),
    ) + frame.payload


def _assert_frame_matches(actual: Frame, expected: Frame) -> None:
    assert isinstance(actual, Frame)
    assert actual.magic == _MAGIC
    assert actual.version == _VERSION
    assert actual.type == expected.type
    assert actual.flags == 0
    assert actual.reserved == 0
    assert actual.request_id == expected.request_id
    assert actual.length == len(expected.payload)
    assert actual.payload == expected.payload
    assert actual == expected


@st.composite
def _valid_frames(draw: st.DrawFn) -> Frame:
    frame_type = draw(
        st.sampled_from(
            [
                FrameType.PING,
                FrameType.PONG,
                FrameType.JOIN,
                FrameType.LEAVE,
                FrameType.MSG,
                FrameType.STATS,
                FrameType.STATS_OK,
            ]
        )
    )
    request_id = draw(_REQUEST_IDS)

    if frame_type in (FrameType.PING, FrameType.PONG):
        payload = _U64.pack(draw(_UNSIGNED_64))
    elif frame_type in (FrameType.JOIN, FrameType.LEAVE):
        payload = _pack_string(draw(_ROOM_NAMES))
    elif frame_type == FrameType.MSG:
        payload = _pack_message(
            draw(_ROOM_NAMES),
            draw(_UNSIGNED_64),
            draw(st.binary(min_size=0, max_size=1024)),
        )
    elif frame_type == FrameType.STATS:
        payload = b""
    else:
        frame_count = draw(st.integers(min_value=0, max_value=0xFFFFFFFF))
        payload = f"frames={frame_count}\n".encode("utf-8")

    return Frame(
        type=frame_type,
        request_id=request_id,
        payload=payload,
    )


@st.composite
def _randomly_sliced_streams(
    draw: st.DrawFn,
) -> tuple[list[Frame], list[int]]:
    frames = draw(
        st.lists(
            _valid_frames(),
            min_size=0,
            max_size=16,
        )
    )
    stream_length = sum(
        _HEADER_SIZE + len(frame.payload)
        for frame in frames
    )

    # Duplicate boundaries also exercise empty feeds between partial frames.
    boundaries = draw(
        st.lists(
            st.integers(min_value=0, max_value=stream_length),
            min_size=0,
            max_size=64,
        )
    )
    boundaries.sort()

    return frames, boundaries


@pytest.mark.parametrize(
    ("frame_type", "request_id", "payload"),
    [
        pytest.param(
            FrameType.PING,
            1,
            _U64.pack(0x0102030405060708),
            id="ping-protocol-vector",
        ),
        pytest.param(
            FrameType.JOIN,
            2,
            _pack_string("general"),
            id="join-protocol-vector",
        ),
        pytest.param(
            FrameType.MSG,
            0xFFFFFFFF,
            _pack_message(
                "room:general",
                0xFFFFFFFFFFFFFFFF,
                b"\x00binary\xffpayload\x00",
            ),
            id="message-with-binary-body",
        ),
        pytest.param(
            FrameType.STATS,
            0,
            b"",
            id="empty-payload",
        ),
        pytest.param(
            FrameType.STATS_OK,
            0,
            b"x" * _MAX_PAYLOAD,
            id="maximum-payload",
        ),
    ],
)
def test_round_trip_happy_path(
    frame_type: FrameType,
    request_id: int,
    payload: bytes,
) -> None:
    expected = Frame(
        type=frame_type,
        request_id=request_id,
        payload=payload,
    )
    packet = _pack_frame(expected)

    assert _HEADER.size == _HEADER_SIZE
    assert len(packet) == _HEADER_SIZE + len(payload)
    assert packet[:2] == b"\xce\x57"
    assert packet[2] == _VERSION
    assert packet[3] == int(frame_type)
    assert packet[4:6] == b"\x00\x00"
    assert packet[6:10] == _U32.pack(request_id)
    assert packet[10:14] == _U32.pack(len(payload))

    decoder = FrameDecoder()
    decoded = decoder.feed(packet)

    assert len(decoded) == 1
    _assert_frame_matches(decoded[0], expected)
    assert decoder.state == "WAIT_HEADER"
    assert decoder.buffered_bytes == 0
    assert decoder.errors == []
    assert decoder.feed(b"") == []


def test_byte_at_a_time_feed() -> None:
    expected = Frame(
        type=FrameType.PING,
        request_id=1,
        payload=_U64.pack(0x0102030405060708),
    )
    packet = bytearray(_pack_frame(expected))
    decoder = FrameDecoder()
    decoded: list[Frame] = []

    assert decoder.state == "WAIT_HEADER"
    assert decoder.feed(b"") == []

    with memoryview(packet) as view:
        for offset in range(len(packet)):
            emitted = decoder.feed(view[offset:offset + 1].tobytes())
            consumed = offset + 1
            decoded.extend(emitted)

            if consumed < len(packet):
                assert emitted == []
                assert decoded == []

                expected_state = (
                    "WAIT_HEADER"
                    if consumed < _HEADER_SIZE
                    else "WAIT_PAYLOAD"
                )
                assert decoder.state == expected_state

                buffered_before_empty_feed = decoder.buffered_bytes
                assert decoder.feed(b"") == []
                assert decoder.state == expected_state
                assert decoder.buffered_bytes == buffered_before_empty_feed
            else:
                assert len(emitted) == 1
                _assert_frame_matches(emitted[0], expected)
                assert decoder.state == "WAIT_HEADER"
                assert decoder.buffered_bytes == 0

    assert decoded == [expected]
    assert decoder.errors == []


def test_multi_frame_single_chunk() -> None:
    expected = [
        Frame(
            type=FrameType.PING,
            request_id=11,
            payload=_U64.pack(0x0102030405060708),
        ),
        Frame(
            type=FrameType.JOIN,
            request_id=12,
            payload=_pack_string("general"),
        ),
        Frame(
            type=FrameType.MSG,
            request_id=13,
            payload=_pack_message(
                "general",
                0x1020304050607080,
                b"\x00hello\xffworld",
            ),
        ),
    ]
    packet = b"".join(_pack_frame(frame) for frame in expected)
    decoder = FrameDecoder()

    decoded = decoder.feed(packet)

    assert len(decoded) == 3
    assert decoded == expected
    for actual, original in zip(decoded, expected, strict=True):
        _assert_frame_matches(actual, original)

    assert decoder.state == "WAIT_HEADER"
    assert decoder.buffered_bytes == 0
    assert decoder.errors == []
    assert decoder.feed(b"") == []


@pytest.mark.parametrize(
    ("max_payload", "claimed_length"),
    [
        pytest.param(0, 1, id="zero-limit"),
        pytest.param(8, 9, id="configured-limit"),
        pytest.param(65_535, 65_536, id="below-protocol-limit"),
        pytest.param(65_536, 65_537, id="above-protocol-limit"),
        pytest.param(65_536, 0xFFFFFFFF, id="maximum-u32-length"),
    ],
)
@pytest.mark.parametrize(
    "frame_type",
    [
        pytest.param(int(FrameType.PING), id="known-type"),
        pytest.param(0x7F, id="unknown-type"),
    ],
)
@pytest.mark.parametrize(
    "fragmented",
    [
        pytest.param(False, id="complete-header"),
        pytest.param(True, id="fragmented-header"),
    ],
)
def test_oversized_header_rejection(
    max_payload: int,
    claimed_length: int,
    frame_type: int,
    fragmented: bool,
) -> None:
    decoder = FrameDecoder(max_payload=max_payload)
    header = _HEADER.pack(
        _MAGIC,
        _VERSION,
        frame_type,
        0,
        0,
        17,
        claimed_length,
    )

    if fragmented:
        assert decoder.feed(header[:-1]) == []
        assert decoder.state == "WAIT_HEADER"
        assert decoder.buffered_bytes == _HEADER_SIZE - 1
        final_chunk = header[-1:]
    else:
        final_chunk = header

    # No body is supplied: rejection must occur from the header alone.
    with pytest.raises(FrameTooLarge) as captured:
        decoder.feed(final_chunk)

    assert captured.value.code == ErrorCode.FRAME_TOO_LARGE
    assert captured.value.fatal is True
    assert captured.value.completed_frames == []
    assert decoder.state == "FAILED"
    assert decoder.buffered_bytes == 0

    # Length validation must precede unknown-type reporting.
    assert decoder.errors == []
    assert decoder.unknown_type_count == 0

    with pytest.raises(FrameTooLarge):
        decoder.feed(b"")


@settings(max_examples=200, deadline=None)
@given(case=_randomly_sliced_streams())
def test_property_random_slicing(
    case: tuple[list[Frame], list[int]],
) -> None:
    expected, random_boundaries = case
    packet = b"".join(_pack_frame(frame) for frame in expected)

    frame_boundaries: list[int] = []
    cumulative_length = 0
    for frame in expected:
        cumulative_length += _HEADER_SIZE + len(frame.payload)
        frame_boundaries.append(cumulative_length)

    boundaries = [0, *random_boundaries, len(packet)]
    decoder = FrameDecoder()
    decoded: list[Frame] = []

    for start, end in zip(boundaries, boundaries[1:]):
        decoded.extend(decoder.feed(packet[start:end]))

        completed_count = sum(
            frame_end <= end
            for frame_end in frame_boundaries
        )
        assert decoded == expected[:completed_count]
        assert decoder.buffered_bytes <= _HEADER_SIZE + _MAX_PAYLOAD

    assert decoded == expected
    for actual, original in zip(decoded, expected, strict=True):
        _assert_frame_matches(actual, original)

    assert decoder.state == "WAIT_HEADER"
    assert decoder.buffered_bytes == 0
    assert decoder.errors == []
    assert decoder.unknown_type_count == 0
    assert decoder.feed(b"") == []

    # A different segmentation of the same stream must produce identical frames.
    assert FrameDecoder().feed(packet) == expected