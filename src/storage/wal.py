from __future__ import annotations

import errno
import fcntl
import os
import re
import stat
import struct
import threading
import zlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from victory.core.router import WalMessage

SEGMENT_MAGIC = b"VWAL"
SEGMENT_VERSION = 1
SEGMENT_HEADER = struct.Struct("!4sBQ")
RECORD_PREFIX = struct.Struct("!II")
RECORD_BODY_HEADER = struct.Struct("!QB")
CHECKSUM_HEADER = struct.Struct("!IQB")
CHECKSUM = struct.Struct("!I")

DEFAULT_SEGMENT_SIZE = 64 * 1024 * 1024
MAX_RECORD_PAYLOAD = 4 + 65536
MAX_RECORD_SIZE = 17 + MAX_RECORD_PAYLOAD
MAX_LSN = (1 << 64) - 1

_SEGMENT_NAME = re.compile(r"wal-([0-9]{8})\.log\Z")


class WalError(RuntimeError):
    """The WAL cannot safely continue accepting records."""


class WalCorruptionError(WalError):
    """Recovery encountered corruption outside a repairable terminal suffix."""


class WalInUseError(WalError):
    """Another WAL instance holds the directory's exclusive ownership lock."""


class RecordType(IntEnum):
    MESSAGE = 1


def _uint(
    name: str,
    value: int,
    maximum: int,
    minimum: int = 0,
) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(
            f"{name} must be an integer in [{minimum}, {maximum}]"
        )


@dataclass(frozen=True, slots=True)
class WalRecord:
    lsn: int
    type: int
    payload: bytes

    def __post_init__(self) -> None:
        _uint("lsn", self.lsn, MAX_LSN, 1)

        if not isinstance(self.type, int) or isinstance(self.type, bool):
            raise ValueError("record type must be an unsigned byte")
        if not 0 <= self.type <= 255:
            raise ValueError("record type must be an unsigned byte")
        if not isinstance(self.payload, bytes):
            raise TypeError("record payload must be immutable bytes")
        if len(self.payload) > MAX_RECORD_PAYLOAD:
            raise ValueError("record payload exceeds the WAL record limit")

    @property
    def wire_size(self) -> int:
        return 17 + len(self.payload)


@dataclass(frozen=True, slots=True)
class RecoverySummary:
    last_lsn: int
    record_count: int
    segment_index: int
    segment_size: int
    truncated_bytes: int


def encode_record(record: WalRecord) -> bytes:
    header = CHECKSUM_HEADER.pack(
        9 + len(record.payload),
        record.lsn,
        record.type,
    )
    checksum = zlib.crc32(
        record.payload,
        zlib.crc32(header),
    ) & 0xFFFFFFFF
    return CHECKSUM.pack(checksum) + header + record.payload


def encode_message(message: WalMessage) -> WalRecord:
    """Persist request correlation together with the exact DELIVER payload."""
    from victory.protocol.codec import Deliver, encode_payload, pack_u32

    payload = pack_u32(message.request_id) + encode_payload(
        Deliver(
            room=message.room,
            origin_node=message.origin_node,
            seq=message.seq,
            sender=message.user,
            client_msg_id=message.client_msg_id,
            body=message.body,
        )
    )

    return WalRecord(
        lsn=message.commit_id,
        type=RecordType.MESSAGE,
        payload=payload,
    )


def decode_message(record: WalRecord) -> WalMessage:
    from victory.core.router import WalMessage
    from victory.protocol.codec import Deliver, decode_payload, unpack_u32
    from victory.protocol.frame import FrameType

    if record.type != RecordType.MESSAGE:
        raise WalCorruptionError(
            f"unsupported WAL record type {record.type}"
        )

    try:
        request_id, offset = unpack_u32(record.payload)
        delivery = decode_payload(
            FrameType.DELIVER,
            memoryview(record.payload)[offset:],
        )

        if not isinstance(delivery, Deliver):
            raise ValueError("WAL message did not decode as DELIVER")

        return WalMessage(
            commit_id=record.lsn,
            origin_node=delivery.origin_node,
            room=delivery.room,
            seq=delivery.seq,
            user=delivery.sender,
            client_msg_id=delivery.client_msg_id,
            body=delivery.body,
            request_id=request_id,
        )
    except Exception as exc:
        raise WalCorruptionError(
            f"invalid message payload at LSN {record.lsn}"
        ) from exc


def _fsync(fd: int) -> None:
    while True:
        try:
            os.fsync(fd)
            return
        except InterruptedError:
            continue


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    offset = 0

    while offset < len(view):
        try:
            written = os.write(fd, view[offset:])
        except InterruptedError:
            continue

        if written <= 0:
            raise OSError(errno.EIO, "WAL write made no progress")

        offset += written


def _pread(fd: int, size: int, offset: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size

    while remaining:
        try:
            chunk = os.pread(fd, remaining, offset)
        except InterruptedError:
            continue

        if not chunk:
            break

        chunks.append(chunk)
        remaining -= len(chunk)
        offset += len(chunk)

    return b"".join(chunks)


def _close(fd: int) -> None:
    if fd >= 0:
        os.close(fd)


def _open_directory(path: Path) -> int:
    return os.open(
        path,
        os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC,
    )


def _ensure_directory(path: Path) -> None:
    missing: list[Path] = []
    cursor = path

    while not cursor.exists():
        missing.append(cursor)
        cursor = cursor.parent

    # A previous boot attempt may have died before syncing this ancestor's
    # entry in its parent directory.
    ancestor_fd = _open_directory(cursor.parent)
    try:
        _fsync(ancestor_fd)
    finally:
        _close(ancestor_fd)

    for directory in reversed(missing):
        try:
            directory.mkdir()
        except FileExistsError:
            if not directory.is_dir():
                raise

        parent_fd = _open_directory(directory.parent)
        try:
            _fsync(parent_fd)
        finally:
            _close(parent_fd)


def _valid_record_after(
    fd: int,
    start: int,
    file_size: int,
) -> bool:
    """Detect later valid records without replaying or allocating the suffix."""
    stride = 64 * 1024

    while start + 17 <= file_size:
        data = _pread(
            fd,
            min(stride + MAX_RECORD_SIZE, file_size - start),
            start,
        )
        view = memoryview(data)
        stop = min(stride, len(data) - 16)

        for offset in range(stop):
            checksum, length = RECORD_PREFIX.unpack_from(view, offset)
            end = offset + 8 + length

            if not 9 <= length <= 9 + MAX_RECORD_PAYLOAD:
                continue
            if end > len(view):
                continue

            lsn = RECORD_BODY_HEADER.unpack_from(view, offset + 8)[0]
            if lsn == 0:
                continue

            calculated = zlib.crc32(
                view[offset + 4:end]
            ) & 0xFFFFFFFF

            if calculated == checksum:
                return True

        start += stride

    return False


class WriteAheadLog:
    """Recover during boot, then transfer disk ownership to the writer.

    on_replay runs synchronously before the reactor starts. Chat recovery can
    use lambda record: router.restore_record(decode_message(record)).

    prepare_batch performs durable segment metadata maintenance.
    append_batch writes within one segment and performs one data fsync.
    """

    def __init__(
        self,
        directory: str | os.PathLike[str],
        *,
        segment_size: int = DEFAULT_SEGMENT_SIZE,
        on_replay: Callable[[WalRecord], None] | None = None,
    ) -> None:
        _uint(
            "segment_size",
            segment_size,
            (1 << 63) - 1,
            SEGMENT_HEADER.size + 17,
        )

        self.directory = Path(directory).absolute()
        self.segment_limit = segment_size

        self._owner: int | None = threading.get_ident()
        self._fd = -1
        self._directory_fd = -1
        self._lock_fd = -1
        self._failed = False
        self._closed = False

        self._index = 0
        self._size = 0
        self._last_lsn = 0
        self._record_count = 0
        self._truncated = 0

        try:
            _ensure_directory(self.directory)
            self._directory_fd = _open_directory(self.directory)
            self._lock_fd = os.open(
                self.directory / "wal.lock",
                os.O_RDWR
                | os.O_CREAT
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
                0o600,
            )

            try:
                fcntl.flock(
                    self._lock_fd,
                    fcntl.LOCK_EX | fcntl.LOCK_NB,
                )
            except BlockingIOError as exc:
                raise WalInUseError(
                    f"WAL directory is already in use: {self.directory}"
                ) from exc

            self._recover(on_replay)

            self.recovery = RecoverySummary(
                last_lsn=self._last_lsn,
                record_count=self._record_count,
                segment_index=self._index,
                segment_size=self._size,
                truncated_bytes=self._truncated,
            )
        except BaseException:
            try:
                self.close()
            except OSError:
                self._closed = True
            raise

    @property
    def last_lsn(self) -> int:
        self._check_owner()
        return self._last_lsn

    @property
    def batch_capacity(self) -> int:
        return self.segment_limit - SEGMENT_HEADER.size

    def _check_owner(self) -> None:
        if self._owner != threading.get_ident():
            raise WalError(
                "WAL access attempted outside its owning thread"
            )
        if self._closed:
            raise WalError("WAL is closed")

    def handoff(self) -> None:
        self._check_owner()
        self._owner = None

    def claim(self) -> None:
        if self._owner is not None or self._closed:
            raise WalError(
                "WAL ownership is not available for transfer"
            )
        self._owner = threading.get_ident()

    def _path(self, index: int) -> Path:
        if index > 99999999:
            raise WalError("WAL segment index exhausted")
        return self.directory / f"wal-{index:08d}.log"

    def _new_segment(self, index: int, first_lsn: int) -> None:
        _uint("first_lsn", first_lsn, MAX_LSN, 1)

        fd = os.open(
            self._path(index),
            os.O_RDWR
            | os.O_CREAT
            | os.O_EXCL
            | os.O_APPEND
            | os.O_CLOEXEC
            | os.O_NOFOLLOW,
            0o600,
        )

        try:
            _write_all(
                fd,
                SEGMENT_HEADER.pack(
                    SEGMENT_MAGIC,
                    SEGMENT_VERSION,
                    first_lsn,
                ),
            )
            _fsync(fd)
            _fsync(self._directory_fd)
        except BaseException:
            _close(fd)
            raise

        previous = self._fd
        self._fd = fd
        self._index = index
        self._size = SEGMENT_HEADER.size
        _close(previous)

    def _repair_tail(
        self,
        fd: int,
        offset: int,
        file_size: int,
        path: Path,
    ) -> None:
        if _valid_record_after(fd, offset + 1, file_size):
            raise WalCorruptionError(
                f"valid record follows damaged WAL data: {path}:{offset}"
            )

        os.ftruncate(fd, offset)
        _fsync(fd)
        self._truncated += file_size - offset

    def _recover(
        self,
        on_replay: Callable[[WalRecord], None] | None,
    ) -> None:
        indices: list[int] = []

        for entry in self.directory.iterdir():
            match = _SEGMENT_NAME.fullmatch(entry.name)

            if match is not None:
                indices.append(int(match.group(1)))
            elif (
                entry.name.startswith("wal-")
                and entry.name.endswith(".log")
            ):
                raise WalCorruptionError(
                    f"invalid segment filename: {entry.name}"
                )

        indices.sort()

        if indices != list(range(len(indices))):
            raise WalCorruptionError(
                "WAL segments are missing or do not start at zero"
            )

        if not indices:
            self._new_segment(0, 1)
            return

        expected_lsn = 1

        for index in indices:
            final = index == indices[-1]
            path = self._path(index)
            fd = os.open(
                path,
                os.O_RDWR
                | os.O_APPEND
                | os.O_CLOEXEC
                | os.O_NOFOLLOW,
            )
            retained = False

            try:
                info = os.fstat(fd)

                if not stat.S_ISREG(info.st_mode):
                    raise WalCorruptionError(
                        f"segment is not a regular file: {path}"
                    )

                size = info.st_size
                header = _pread(fd, SEGMENT_HEADER.size, 0)

                if len(header) != SEGMENT_HEADER.size:
                    if not final:
                        raise WalCorruptionError(
                            f"truncated historical segment header: {path}"
                        )

                    expected_header = SEGMENT_HEADER.pack(
                        SEGMENT_MAGIC,
                        SEGMENT_VERSION,
                        expected_lsn,
                    )

                    if not expected_header.startswith(header):
                        raise WalCorruptionError(
                            f"corrupt final segment header: {path}"
                        )

                    self._truncated += size
                    os.ftruncate(fd, 0)
                    _write_all(fd, expected_header)
                    _fsync(fd)

                    header = expected_header
                    size = SEGMENT_HEADER.size

                magic, version, first_lsn = SEGMENT_HEADER.unpack(header)

                if (
                    magic != SEGMENT_MAGIC
                    or version != SEGMENT_VERSION
                    or first_lsn != expected_lsn
                ):
                    raise WalCorruptionError(
                        f"invalid segment header: {path}"
                    )

                offset = SEGMENT_HEADER.size

                while offset < size:
                    prefix = _pread(
                        fd,
                        RECORD_PREFIX.size,
                        offset,
                    )

                    if len(prefix) != RECORD_PREFIX.size:
                        if not final:
                            raise WalCorruptionError(
                                f"short historical record: {path}:{offset}"
                            )

                        self._repair_tail(fd, offset, size, path)
                        size = offset
                        break

                    checksum, length = RECORD_PREFIX.unpack(prefix)

                    if not 9 <= length <= 9 + MAX_RECORD_PAYLOAD:
                        if not final:
                            raise WalCorruptionError(
                                "invalid historical record length: "
                                f"{path}:{offset}"
                            )

                        self._repair_tail(fd, offset, size, path)
                        size = offset
                        break

                    body = _pread(
                        fd,
                        length,
                        offset + RECORD_PREFIX.size,
                    )
                    valid = (
                        len(body) == length
                        and (
                            zlib.crc32(
                                body,
                                zlib.crc32(prefix[4:]),
                            ) & 0xFFFFFFFF
                        ) == checksum
                    )

                    if not valid:
                        if not final:
                            raise WalCorruptionError(
                                f"damaged historical record: {path}:{offset}"
                            )

                        self._repair_tail(fd, offset, size, path)
                        size = offset
                        break

                    lsn, record_type = RECORD_BODY_HEADER.unpack_from(body)

                    if lsn != expected_lsn:
                        raise WalCorruptionError(
                            f"noncontiguous LSN at {path}:{offset}"
                        )

                    record = WalRecord(
                        lsn=lsn,
                        type=record_type,
                        payload=body[RECORD_BODY_HEADER.size:],
                    )

                    if on_replay is not None:
                        on_replay(record)

                    expected_lsn += 1
                    self._last_lsn = lsn
                    self._record_count += 1
                    offset += RECORD_PREFIX.size + length

                if not final and offset == SEGMENT_HEADER.size:
                    raise WalCorruptionError(
                        f"empty historical segment: {path}"
                    )

                if final:
                    self._fd = fd
                    self._index = index
                    self._size = size
                    retained = True
            finally:
                if not retained:
                    _close(fd)

        # A previous process may have died with valid records in page cache.
        # Persist the recovered prefix before a retry can receive a durable ACK.
        _fsync(self._fd)
        _fsync(self._directory_fd)

    def prepare_batch(self, byte_count: int) -> None:
        """Perform metadata maintenance before committing a data batch."""
        self._check_owner()
        _uint("byte_count", byte_count, self.batch_capacity, 1)

        if self._failed:
            raise WalError(
                "WAL is poisoned; restart and recover before writing again"
            )

        try:
            if self._size + byte_count > self.segment_limit:
                self._new_segment(
                    self._index + 1,
                    self._last_lsn + 1,
                )
        except BaseException:
            self._failed = True
            raise

    def append_batch(self, records: Sequence[WalRecord]) -> int:
        """Return the batch's final LSN only after its data fsync succeeds."""
        self._check_owner()

        if self._failed:
            raise WalError(
                "WAL is poisoned; restart and recover before writing again"
            )
        if not records:
            raise ValueError("a WAL commit batch must not be empty")

        expected = self._last_lsn + 1
        encoded: list[bytes] = []

        for record in records:
            if record.lsn != expected:
                raise ValueError(
                    f"expected LSN {expected}, received {record.lsn}"
                )

            encoded.append(encode_record(record))
            expected += 1

        data = b"".join(encoded)

        if self._size + len(data) > self.segment_limit:
            raise WalError(
                "batch does not fit; call prepare_batch before append_batch"
            )

        try:
            _write_all(self._fd, data)
            _fsync(self._fd)
        except BaseException:
            self._failed = True
            raise

        self._size += len(data)
        self._last_lsn = records[-1].lsn
        return self._last_lsn

    def close(self) -> None:
        if self._closed:
            return
        if self._owner != threading.get_ident():
            raise WalError(
                "only the WAL owner may close its descriptors"
            )

        self._closed = True
        first_error: OSError | None = None

        for name in ("_fd", "_directory_fd", "_lock_fd"):
            fd = getattr(self, name)
            setattr(self, name, -1)

            try:
                _close(fd)
            except OSError as exc:
                if first_error is None:
                    first_error = exc

        if first_error is not None:
            raise first_error