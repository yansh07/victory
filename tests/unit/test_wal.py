from __future__ import annotations

import errno
import os
import selectors
import signal
import struct
import subprocess
import sys
import threading
import time
import zlib
from collections import deque
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from victory.storage import wal as wal_module
from victory.storage.wal import (
    SEGMENT_HEADER,
    SEGMENT_MAGIC,
    SEGMENT_VERSION,
    RecordType,
    WalCorruptionError,
    WalRecord,
    WriteAheadLog,
    encode_record,
)
from victory.storage.writer_thread import WalWriter, WriterState

WAIT_SECONDS = 10.0
FRAME_HEADER = struct.Struct("!HBBBBII")
ACK_PAYLOAD = struct.Struct("!BBQ")
RECORD_HEADER = struct.Struct("!IIQB")
UINT16 = struct.Struct("!H")
UINT32 = struct.Struct("!I")
UINT64 = struct.Struct("!Q")


@dataclass(frozen=True, slots=True)
class _Message:
    commit_id: int
    origin_node: int
    room: str
    seq: int
    user: str
    client_msg_id: int
    body: bytes
    request_id: int


def _messages(count: int) -> list[_Message]:
    rooms = ("general", "systems", "random")
    sequences: dict[str, int] = {}
    messages: list[_Message] = []

    for lsn in range(1, count + 1):
        room = rooms[(lsn - 1) % len(rooms)]
        seq = sequences.get(room, 0) + 1
        sequences[room] = seq
        messages.append(
            _Message(
                commit_id=lsn,
                origin_node=17,
                room=room,
                seq=seq,
                user="Alice" if lsn % 2 else "Bob",
                client_msg_id=9000 + lsn,
                body=b"message-" + lsn.to_bytes(2, "big") + b"\x00\xff",
                request_id=1000 + lsn,
            )
        )

    return messages


def _length_prefixed(data: bytes) -> bytes:
    return UINT16.pack(len(data)) + data


def _record(message: _Message) -> WalRecord:
    payload = b"".join(
        (
            UINT32.pack(message.request_id),
            _length_prefixed(message.room.encode("ascii")),
            UINT32.pack(message.origin_node),
            UINT64.pack(message.seq),
            _length_prefixed(message.user.encode("ascii")),
            UINT64.pack(message.client_msg_id),
            _length_prefixed(message.body),
        )
    )
    return WalRecord(message.commit_id, RecordType.MESSAGE, payload)


def _manual_record(record: WalRecord) -> bytes:
    covered = struct.pack(
        "!IQB",
        9 + len(record.payload),
        record.lsn,
        record.type,
    )
    covered += record.payload
    return UINT32.pack(zlib.crc32(covered) & 0xFFFFFFFF) + covered


def _ack_packet(message: _Message) -> bytes:
    payload = ACK_PAYLOAD.pack(0x04, 1, message.seq)
    return FRAME_HEADER.pack(
        0xCE57,
        1,
        0x07,
        0,
        0,
        message.request_id,
        len(payload),
    ) + payload


def _parse_message(record: WalRecord) -> _Message:
    assert record.type == RecordType.MESSAGE
    payload = memoryview(record.payload)
    offset = 0

    def take(size: int) -> memoryview:
        nonlocal offset
        assert size >= 0 and offset + size <= len(payload)
        result = payload[offset:offset + size]
        offset += size
        return result

    def take_field() -> bytes:
        size = UINT16.unpack(take(UINT16.size))[0]
        return bytes(take(size))

    request_id = UINT32.unpack(take(UINT32.size))[0]
    room = take_field().decode("ascii")
    origin_node = UINT32.unpack(take(UINT32.size))[0]
    seq = UINT64.unpack(take(UINT64.size))[0]
    user = take_field().decode("ascii")
    client_msg_id = UINT64.unpack(take(UINT64.size))[0]
    body = take_field()

    assert offset == len(payload)

    return _Message(
        commit_id=record.lsn,
        origin_node=origin_node,
        room=room,
        seq=seq,
        user=user,
        client_msg_id=client_msg_id,
        body=body,
        request_id=request_id,
    )


@dataclass(slots=True)
class _ReplayState:
    """Independent application replay sink for sequence and dedupe checks."""

    next_lsn: int = 1
    room_sequences: dict[tuple[int, str], int] = field(
        default_factory=dict
    )
    deduplication: dict[tuple[str, int], bytes] = field(
        default_factory=dict
    )
    messages: list[_Message] = field(default_factory=list)

    def apply(self, record: WalRecord) -> None:
        assert record.lsn == self.next_lsn
        message = _parse_message(record)
        room_key = (message.origin_node, message.room)

        assert message.seq == self.room_sequences.get(room_key, 0) + 1

        deduplication_key = (message.user, message.client_msg_id)
        assert deduplication_key not in self.deduplication

        self.room_sequences[room_key] = message.seq
        self.deduplication[deduplication_key] = _ack_packet(message)
        self.messages.append(message)
        self.next_lsn += 1


@dataclass(frozen=True, slots=True)
class _BackendEvent:
    fd: int
    mask: int
    data: object


class _PollBackend:
    """Kernel-backed implementation of the writer's backend contract."""

    def __init__(self) -> None:
        self.selector = selectors.DefaultSelector()

    def register(
        self,
        fd: int,
        mask: int,
        data: object = None,
    ) -> None:
        assert mask == selectors.EVENT_READ
        assert not os.get_blocking(fd)
        self.selector.register(fd, selectors.EVENT_READ, data)

    def unregister(self, fd: int) -> None:
        try:
            self.selector.unregister(fd)
        except KeyError:
            return

    def poll(self, timeout: float | None) -> list[_BackendEvent]:
        return [
            _BackendEvent(key.fd, mask, key.data)
            for key, mask in self.selector.select(timeout)
        ]

    def close(self) -> None:
        self.selector.close()


@dataclass(frozen=True, slots=True)
class _AckAction:
    packet: bytes


@dataclass(frozen=True, slots=True)
class _FatalAction:
    failed_lsn: int
    message: str


class _DurabilityRouter:
    """Router double; the real writer controls callback timing."""

    def __init__(
        self,
        messages: Sequence[_Message],
        durability_confirmed: threading.Event,
    ) -> None:
        self.owner = threading.get_ident()
        self.pending = {
            message.commit_id: message for message in messages
        }
        self.durability_confirmed = durability_confirmed
        self.committed: list[int] = []
        self.failures: list[int] = []

    @property
    def pending_count(self) -> int:
        return len(self.pending)

    def wal_committed(self, commit_id: int) -> list[_AckAction]:
        assert threading.get_ident() == self.owner
        assert self.durability_confirmed.is_set()
        assert commit_id == len(self.committed) + 1

        message = self.pending.pop(commit_id)
        self.committed.append(commit_id)
        return [_AckAction(_ack_packet(message))]

    def wal_failed(
        self,
        commit_id: int,
        message: str,
    ) -> list[_FatalAction]:
        assert threading.get_ident() == self.owner
        assert commit_id in self.pending

        self.failures.append(commit_id)
        self.pending.clear()
        return [_FatalAction(commit_id, message)]

    def begin_shutdown(self, deadline_ms: int) -> list[_FatalAction]:
        assert threading.get_ident() == self.owner
        assert deadline_ms == 0

        self.pending.clear()
        return [_FatalAction(0, "storage shutdown")]


@dataclass(slots=True)
class _ClientState:
    durable_ack_count: int = 0
    packets: list[bytes] = field(default_factory=list)

    def deliver(
        self,
        actions: Sequence[_AckAction | _FatalAction],
    ) -> None:
        for action in actions:
            assert isinstance(action, _AckAction)

            header = FRAME_HEADER.unpack_from(action.packet)
            assert header[:5] == (0xCE57, 1, 0x07, 0, 0)
            assert header[6] == ACK_PAYLOAD.size
            assert len(action.packet) == (
                FRAME_HEADER.size + ACK_PAYLOAD.size
            )

            acked_type, durable, seq = ACK_PAYLOAD.unpack_from(
                action.packet,
                FRAME_HEADER.size,
            )
            assert acked_type == 0x04
            assert durable == 1
            assert seq > 0

            self.durable_ack_count += 1
            self.packets.append(action.packet)


@contextmanager
def _running_writer(
    log: WriteAheadLog,
    backend: _PollBackend,
    release_events: Sequence[threading.Event] = (),
) -> Iterator[WalWriter]:
    writer = WalWriter(log, backend)

    try:
        writer.start()
        yield writer
    finally:
        for event in release_events:
            event.set()

        try:
            assert writer.close(WAIT_SECONDS), "WAL worker did not stop"
            writer.drain_completions()
        finally:
            backend.close()


def _next_events(backend: _PollBackend) -> list[_BackendEvent]:
    deadline = time.monotonic() + WAIT_SECONDS

    while True:
        remaining = deadline - time.monotonic()
        assert remaining > 0, "WAL worker did not notify the reactor"

        events = backend.poll(remaining)
        if events:
            return events


def _write_records(
    directory: Path,
    records: Sequence[WalRecord],
    segment_size: int = 512,
) -> None:
    log = WriteAheadLog(directory, segment_size=segment_size)

    try:
        for record in records:
            log.prepare_batch(record.wire_size)
            log.append_batch([record])
    finally:
        log.close()


def _disk_records(directory: Path) -> list[WalRecord]:
    records: list[WalRecord] = []
    paths = sorted(directory.glob("wal-*.log"))
    assert paths
    next_lsn = 1

    for index, path in enumerate(paths):
        assert path.name == f"wal-{index:08d}.log"
        data = path.read_bytes()

        assert len(data) >= SEGMENT_HEADER.size
        assert SEGMENT_HEADER.unpack_from(data) == (
            SEGMENT_MAGIC,
            SEGMENT_VERSION,
            next_lsn,
        )

        offset = SEGMENT_HEADER.size

        while offset < len(data):
            assert len(data) - offset >= RECORD_HEADER.size
            checksum, length, lsn, record_type = (
                RECORD_HEADER.unpack_from(data, offset)
            )

            assert length >= 9
            end = offset + 8 + length
            assert end <= len(data)

            calculated = zlib.crc32(
                memoryview(data)[offset + 4:end]
            ) & 0xFFFFFFFF

            assert checksum == calculated
            assert lsn == next_lsn

            record = WalRecord(
                lsn,
                record_type,
                data[offset + RECORD_HEADER.size:end],
            )
            assert data[offset:end] == _manual_record(record)

            records.append(record)
            next_lsn += 1
            offset = end

        assert offset == len(data)

    return records


def _append_bytes(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_APPEND)

    try:
        view = memoryview(data)
        offset = 0

        while offset < len(view):
            try:
                written = os.write(fd, view[offset:])
            except InterruptedError:
                continue

            assert written > 0
            offset += written

        os.fsync(fd)
    finally:
        os.close(fd)


def _flip_byte(path: Path, offset: int) -> None:
    with path.open("r+b", buffering=0) as stream:
        stream.seek(offset)
        original = stream.read(1)
        assert len(original) == 1

        stream.seek(offset)
        changed = bytes([original[0] ^ 0x80])
        assert stream.write(changed) == 1
        os.fsync(stream.fileno())


@pytest.mark.parametrize("batch_size", [1, 50])
def test_ack_released_only_after_fsync_and_reactor_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    batch_size: int,
) -> None:
    messages = _messages(batch_size)
    records = [_record(message) for message in messages]
    log = WriteAheadLog(tmp_path / "wal")
    data_fd = log._fd
    owner = threading.get_ident()

    worker_waiting = threading.Event()
    allow_dequeue = threading.Event()
    fsync_entered = threading.Event()
    allow_fsync = threading.Event()
    durability_confirmed = threading.Event()

    fsync_calls: deque[int] = deque()
    write_calls: deque[int] = deque()

    original_claim = log.claim
    original_fsync = wal_module._fsync
    original_write = os.write

    def gated_claim() -> None:
        worker_waiting.set()
        assert allow_dequeue.wait(
            WAIT_SECONDS
        ), "dequeue barrier timed out"
        original_claim()

    def gated_fsync(fd: int) -> None:
        if fd == data_fd:
            assert threading.get_ident() != owner
            fsync_calls.append(fd)
            fsync_entered.set()

            assert allow_fsync.wait(
                WAIT_SECONDS
            ), "fsync barrier timed out"

            original_fsync(fd)
            durability_confirmed.set()
        else:
            original_fsync(fd)

    def counted_write(
        fd: int,
        data: bytes | memoryview,
    ) -> int:
        if fd == data_fd:
            assert threading.get_ident() != owner
            write_calls.append(len(data))
        return original_write(fd, data)

    monkeypatch.setattr(log, "claim", gated_claim)
    monkeypatch.setattr(wal_module, "_fsync", gated_fsync)
    monkeypatch.setattr(os, "write", counted_write)

    backend = _PollBackend()
    router = _DurabilityRouter(messages, durability_confirmed)
    client = _ClientState()

    with _running_writer(
        log,
        backend,
        [allow_dequeue, allow_fsync],
    ) as writer:
        assert worker_waiting.wait(WAIT_SECONDS)

        for record in records:
            assert writer.submit_record(record)

        assert list(writer._requests) == records
        assert writer.pending_count == batch_size
        assert writer.pending_bytes == sum(
            record.wire_size for record in records
        )
        assert writer.durable_lsn == 0
        assert not fsync_calls
        assert not write_calls
        assert backend.poll(0.0) == []
        assert writer.drain_actions(router) == []
        assert client.durable_ack_count == 0
        assert router.committed == []

        allow_dequeue.set()
        assert fsync_entered.wait(WAIT_SECONDS)

        assert not durability_confirmed.is_set()
        assert writer.durable_lsn == 0
        assert backend.poll(0.0) == []
        assert writer.drain_actions(router) == []
        assert client.durable_ack_count == 0
        assert router.committed == []

        allow_fsync.set()
        events = _next_events(backend)

        assert durability_confirmed.is_set()
        assert client.durable_ack_count == 0
        assert router.committed == []
        assert writer.durable_lsn == 0

        for event in events:
            assert event.data is writer
            assert event.fd == writer.fileno()
            client.deliver(writer.handle_event(event, router))

        assert list(fsync_calls) == [data_fd]
        assert list(write_calls) == [
            sum(record.wire_size for record in records)
        ]
        assert router.committed == list(range(1, batch_size + 1))
        assert client.durable_ack_count == batch_size
        assert client.packets == [
            _ack_packet(message) for message in messages
        ]
        assert writer.durable_lsn == batch_size
        assert writer.pending_count == 0
        assert writer.pending_bytes == 0
        assert _disk_records(tmp_path / "wal") == records


_CHILD_SOURCE = r'''
import select
import selectors
import struct
import sys
import time
import zlib

from victory.storage.wal import WalRecord, WriteAheadLog
from victory.storage.writer_thread import WalWriter, WriterFailure


class Backend:
    def __init__(self) -> None:
        self.selector = selectors.DefaultSelector()

    def register(
        self,
        fd: int,
        mask: int,
        data: object = None,
    ) -> None:
        self.selector.register(fd, mask, data)

    def unregister(self, fd: int) -> None:
        self.selector.unregister(fd)


encoded = bytes.fromhex(sys.argv[2])
records = []
offset = 0

while offset < len(encoded):
    checksum, length, lsn, record_type = struct.unpack_from(
        "!IIQB", encoded, offset
    )
    end = offset + 8 + length

    if end > len(encoded):
        raise RuntimeError("truncated child fixture")

    calculated = zlib.crc32(encoded[offset + 4:end]) & 0xffffffff

    if calculated != checksum:
        raise RuntimeError("invalid child fixture checksum")

    records.append(
        WalRecord(lsn, record_type, encoded[offset + 17:end])
    )
    offset = end

log = WriteAheadLog(sys.argv[1], segment_size=512)
backend = Backend()
writer = WalWriter(log, backend)
writer.start()

for record in records:
    if not writer.submit_record(record):
        raise RuntimeError("unexpected admission backpressure")

deadline = time.monotonic() + 10.0

while writer.durable_lsn != records[-1].lsn:
    remaining = deadline - time.monotonic()

    if remaining <= 0:
        raise RuntimeError("child commit timed out")

    for key, mask in backend.selector.select(remaining):
        for completion in writer.drain_completions():
            if isinstance(completion, WriterFailure):
                raise RuntimeError(completion.message)

sys.stdout.write("READY\n")
sys.stdout.flush()

select.select([sys.stdin.fileno()], [], [])
raise RuntimeError("control pipe closed without killing the node")
'''


def _wait_for_child_ready(
    process: subprocess.Popen[bytes],
) -> None:
    assert process.stdout is not None
    fd = process.stdout.fileno()
    os.set_blocking(fd, False)

    output = bytearray()
    deadline = time.monotonic() + WAIT_SECONDS

    with selectors.DefaultSelector() as selector:
        selector.register(fd, selectors.EVENT_READ)

        while b"\n" not in output:
            remaining = deadline - time.monotonic()
            assert remaining > 0, (
                f"child startup timed out: {bytes(output)!r}"
            )

            for key, mask in selector.select(remaining):
                try:
                    chunk = os.read(key.fd, 4096)
                except (BlockingIOError, InterruptedError):
                    continue

                assert chunk, (
                    "child exited before committing: "
                    f"{bytes(output)!r}"
                )
                output.extend(chunk)

    assert bytes(output) == b"READY\n", bytes(output).decode(
        "utf-8", "replace"
    )


@pytest.mark.skipif(
    os.name != "posix",
    reason="requires POSIX SIGKILL semantics",
)
def test_hard_crash_replays_fifty_records_and_restores_room_state(
    tmp_path: Path,
) -> None:
    messages = _messages(50)
    records = [_record(message) for message in messages]
    directory = tmp_path / "wal"

    environment = os.environ.copy()
    source_root = str(
        Path(wal_module.__file__).resolve().parents[2]
    )
    inherited_path = environment.get("PYTHONPATH")

    environment["PYTHONPATH"] = (
        source_root + os.pathsep + inherited_path
        if inherited_path
        else source_root
    )

    encoded_records = b"".join(
        _manual_record(record) for record in records
    )

    process = subprocess.Popen(
        [
            sys.executable,
            "-c",
            _CHILD_SOURCE,
            str(directory),
            encoded_records.hex(),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=environment,
        cwd=tmp_path,
        bufsize=0,
    )

    try:
        _wait_for_child_ready(process)

        assert process.poll() is None
        assert _disk_records(directory) == records
        assert len(list(directory.glob("wal-*.log"))) > 1

        process.kill()
        assert process.wait(WAIT_SECONDS) == -signal.SIGKILL
    finally:
        if process.poll() is None:
            process.kill()

        process.wait(WAIT_SECONDS)

        if process.stdin is not None:
            process.stdin.close()
        if process.stdout is not None:
            process.stdout.close()

    restored = _ReplayState()
    log = WriteAheadLog(
        directory,
        segment_size=512,
        on_replay=restored.apply,
    )

    try:
        assert log.recovery.last_lsn == 50
        assert log.recovery.record_count == 50
        assert log.recovery.truncated_bytes == 0
        assert restored.next_lsn == 51
        assert restored.messages == messages

        expected_sequences: dict[tuple[int, str], int] = {}

        for message in messages:
            room_key = (message.origin_node, message.room)
            expected_sequences[room_key] = message.seq
            deduplication_key = (
                message.user,
                message.client_msg_id,
            )
            assert restored.deduplication[deduplication_key] == (
                _ack_packet(message)
            )

        assert restored.room_sequences == expected_sequences

        next_message = _Message(
            commit_id=restored.next_lsn,
            origin_node=17,
            room="general",
            seq=restored.room_sequences[(17, "general")] + 1,
            user="Alice",
            client_msg_id=99999,
            body=b"after-recovery",
            request_id=2000,
        )
        next_record = _record(next_message)

        log.prepare_batch(next_record.wire_size)
        assert log.append_batch([next_record]) == 51
    finally:
        log.close()

    replayed_again = _ReplayState()
    log = WriteAheadLog(
        directory,
        segment_size=512,
        on_replay=replayed_again.apply,
    )

    try:
        assert replayed_again.messages == messages + [next_message]
        assert replayed_again.next_lsn == 52
        assert replayed_again.room_sequences[(17, "general")] == (
            next_message.seq
        )
        assert _disk_records(directory) == records + [next_record]
    finally:
        log.close()


@pytest.mark.parametrize(
    "damage",
    [
        "short_crc",
        "short_length",
        "short_lsn",
        "missing_type",
        "short_payload",
        "bad_crc",
        "bad_payload_crc",
        "invalid_length",
    ],
)
def test_terminal_torn_tail_is_truncated_to_verified_boundary(
    tmp_path: Path,
    damage: str,
) -> None:
    messages = _messages(7)
    prefix = [_record(message) for message in messages[:6]]
    directory = tmp_path / "wal"

    _write_records(directory, prefix, segment_size=256)

    paths = sorted(directory.glob("wal-*.log"))
    assert len(paths) >= 2

    final_path = paths[-1]
    before = {path: path.read_bytes() for path in paths}
    boundary = final_path.stat().st_size
    complete = _manual_record(_record(messages[-1]))

    cuts = {
        "short_crc": 2,
        "short_length": 6,
        "short_lsn": 12,
        "missing_type": 16,
        "short_payload": len(complete) - 1,
    }

    if damage in cuts:
        tail = complete[:cuts[damage]]
    else:
        changed = bytearray(complete)

        if damage == "bad_crc":
            changed[0] ^= 0x80
        elif damage == "bad_payload_crc":
            changed[-1] ^= 0x80
        else:
            UINT32.pack_into(changed, 4, 0xFFFFFFFF)

        tail = bytes(changed)

    _append_bytes(final_path, tail)
    assert final_path.stat().st_size == boundary + len(tail)

    state = _ReplayState()
    log = WriteAheadLog(
        directory,
        segment_size=256,
        on_replay=state.apply,
    )

    try:
        assert state.messages == messages[:6]
        assert state.next_lsn == 7
        assert log.recovery.last_lsn == 6
        assert log.recovery.record_count == 6
        assert log.recovery.truncated_bytes == len(tail)
        assert final_path.stat().st_size == boundary

        for path in paths:
            assert path.read_bytes() == before[path]

        assert _disk_records(directory) == prefix
    finally:
        log.close()

    second_state = _ReplayState()
    log = WriteAheadLog(
        directory,
        segment_size=256,
        on_replay=second_state.apply,
    )

    try:
        assert log.recovery.truncated_bytes == 0
        assert second_state.messages == messages[:6]
    finally:
        log.close()


@pytest.mark.parametrize("field_offset", [0, 4, 8, 16, 17])
def test_historical_mid_file_corruption_aborts_without_truncation(
    tmp_path: Path,
    field_offset: int,
) -> None:
    records = [_record(message) for message in _messages(50)]
    directory = tmp_path / "wal"

    _write_records(directory, records, segment_size=512)

    paths = sorted(directory.glob("wal-*.log"))
    assert len(paths) > 1

    historical = paths[0]
    second_record_offset = (
        SEGMENT_HEADER.size + records[0].wire_size
    )
    assert (
        second_record_offset + records[1].wire_size
        <= historical.stat().st_size
    )

    _flip_byte(historical, second_record_offset + field_offset)

    corrupted_files = {
        path: path.read_bytes() for path in paths
    }
    replayed: list[WalRecord] = []

    with pytest.raises(WalCorruptionError):
        WriteAheadLog(
            directory,
            segment_size=512,
            on_replay=replayed.append,
        )

    assert replayed == records[:1]

    for path in paths:
        assert path.read_bytes() == corrupted_files[path]

    with pytest.raises(WalCorruptionError):
        WriteAheadLog(directory, segment_size=512)


def test_final_segment_corruption_followed_by_valid_record_is_fatal(
    tmp_path: Path,
) -> None:
    records = [_record(message) for message in _messages(3)]
    directory = tmp_path / "wal"

    _write_records(directory, records, segment_size=4096)

    path = directory / "wal-00000000.log"
    middle_offset = SEGMENT_HEADER.size + records[0].wire_size
    _flip_byte(path, middle_offset)

    damaged = path.read_bytes()
    replayed: list[WalRecord] = []

    with pytest.raises(WalCorruptionError):
        WriteAheadLog(directory, on_replay=replayed.append)

    assert replayed == records[:1]
    assert path.read_bytes() == damaged


def test_record_layout_and_crc_cover_every_required_field() -> None:
    for message in _messages(50):
        record = _record(message)
        packed = encode_record(record)

        assert packed == _manual_record(record)

        checksum, length, lsn, record_type = (
            RECORD_HEADER.unpack_from(packed)
        )
        assert length == 9 + len(record.payload)
        assert len(packed) == 8 + length
        assert lsn == record.lsn
        assert record_type == RecordType.MESSAGE
        assert checksum == zlib.crc32(packed[4:]) & 0xFFFFFFFF
        assert packed[RECORD_HEADER.size:] == record.payload
        assert _parse_message(record) == message


def test_short_writes_and_interrupted_write_use_one_data_fsync(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    records = [_record(message) for message in _messages(3)]
    directory = tmp_path / "wal"
    log = WriteAheadLog(directory)
    data_fd = log._fd

    log.prepare_batch(
        sum(record.wire_size for record in records)
    )

    original_write = os.write
    original_fsync = wal_module._fsync
    write_calls = 0
    sync_calls: list[int] = []

    def short_write(
        fd: int,
        data: bytes | memoryview,
    ) -> int:
        nonlocal write_calls

        if fd == data_fd:
            write_calls += 1

            if write_calls == 1:
                raise InterruptedError(
                    errno.EINTR,
                    "injected interrupted write",
                )

            return original_write(fd, memoryview(data)[:3])

        return original_write(fd, data)

    def counted_fsync(fd: int) -> None:
        sync_calls.append(fd)
        original_fsync(fd)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(os, "write", short_write)
            patch.setattr(wal_module, "_fsync", counted_fsync)
            assert log.append_batch(records) == 3

        assert write_calls > len(records)
        assert sync_calls == [data_fd]
    finally:
        log.close()

    assert _disk_records(directory) == records


def test_fsync_failure_is_fatal_and_never_releases_an_ack(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    messages = _messages(1)
    directory = tmp_path / "wal"
    log = WriteAheadLog(directory)
    data_fd = log._fd
    original_fsync = wal_module._fsync

    durability_confirmed = threading.Event()
    router = _DurabilityRouter(messages, durability_confirmed)
    backend = _PollBackend()

    def failing_fsync(fd: int) -> None:
        if fd == data_fd:
            raise OSError(
                errno.ENOSPC,
                "injected durability failure",
            )
        original_fsync(fd)

    monkeypatch.setattr(wal_module, "_fsync", failing_fsync)

    with _running_writer(log, backend) as writer:
        assert writer.submit_record(_record(messages[0]))

        actions: list[_AckAction | _FatalAction] = []
        deadline = time.monotonic() + WAIT_SECONDS

        while not router.failures:
            assert time.monotonic() < deadline, (
                "storage failure was not delivered"
            )

            for event in _next_events(backend):
                actions.extend(
                    writer.handle_event(event, router)
                )

        assert router.committed == []
        assert router.failures == [1]
        assert actions
        assert all(
            isinstance(action, _FatalAction)
            for action in actions
        )
        assert not durability_confirmed.is_set()
        assert writer.durable_lsn == 0
        assert writer.state == WriterState.FAILED