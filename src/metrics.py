from __future__ import annotations

from array import array
from enum import IntEnum
from io import StringIO
from typing import TextIO

UINT64_MAX = (1 << 64) - 1
HISTOGRAM_BUCKETS = 65


class Metric(IntEnum):
    CONNECTIONS = 0
    CONNECTIONS_PEAK = 1
    ACCEPTED = 2
    CLOSED = 3
    REJECTED = 4
    CLIENT_BYTES_IN = 5
    CLIENT_BYTES_OUT = 6
    FRAMES_IN = 7
    FRAMES_QUEUED = 8
    OUTBOUND_BYTES = 9
    OUTBOUND_PEAK = 10
    READ_PAUSES = 11
    READ_RESUMES = 12
    SLOW_CONSUMERS = 13
    PROTOCOL_ERRORS = 14
    WAL_PENDING = 15
    WAL_BATCHES = 16
    WAL_RECORDS = 17
    WAL_BYTES = 18
    WAL_FAILURES = 19
    WAL_RECOVERED = 20
    WAL_DURABLE_LSN = 21
    BUS_BYTES_IN = 22
    BUS_BYTES_OUT = 23
    BUS_PUBLISHED = 24
    BUS_RECEIVED = 25
    BUS_DROPPED = 26
    BUS_ERRORS = 27
    BUS_PUBLISHER_CONNECTED = 28
    BUS_SUBSCRIBER_CONNECTED = 29
    LOOP_PASSES = 30
    TIMER_CALLBACKS = 31
    SHUTDOWN_STATE = 32


_NAMES = (
    "connections.current",
    "connections.peak",
    "connections.accepted_total",
    "connections.closed_total",
    "connections.rejected_total",
    "client.bytes_in_total",
    "client.bytes_out_total",
    "client.frames_in_total",
    "client.application_frames_queued_total",
    "outbound.bytes_current",
    "outbound.bytes_peak",
    "backpressure.read_pauses_total",
    "backpressure.read_resumes_total",
    "backpressure.slow_consumers_total",
    "decoder.errors_total",
    "wal.pending_records",
    "wal.batches_total",
    "wal.records_total",
    "wal.bytes_total",
    "wal.failures_total",
    "wal.recovered_records",
    "wal.durable_lsn",
    "bus.bytes_in_total",
    "bus.bytes_out_total",
    "bus.publish_accepted_total",
    "bus.received_total",
    "bus.server_dropped_total",
    "bus.server_errors_total",
    "bus.publisher_connected",
    "bus.subscriber_connected",
    "loop.passes_total",
    "timers.callbacks_total",
    "shutdown.state",
)


def _nonnegative(value: int) -> None:
    if type(value) is not int or value < 0:
        raise ValueError("metric values must be nonnegative integers")


class LogHistogram:
    """Fixed-storage histogram for unsigned integer samples.

    Bucket zero contains zero. Bucket k contains [2**(k-1), 2**k-1].
    Recording never grows a container or retains sample objects.

    CPython integer arithmetic can allocate temporary objects. Fixed histogram
    storage is guaranteed; literally allocation-free Python execution and
    diagnostic text formatting are not.
    """

    __slots__ = ("_buckets", "_state")

    def __init__(self) -> None:
        self._buckets = array("Q", [0]) * HISTOGRAM_BUCKETS
        self._state = array("Q", [0, 0, UINT64_MAX, 0])

    @property
    def count(self) -> int:
        return self._state[0]

    @property
    def total(self) -> int:
        return self._state[1]

    @property
    def minimum(self) -> int:
        return self._state[2] if self._state[0] else 0

    @property
    def maximum(self) -> int:
        return self._state[3]

    def observe(self, value: int) -> None:
        _nonnegative(value)

        if value > UINT64_MAX:
            value = UINT64_MAX

        index = value.bit_length()
        count = self._buckets[index]

        if count < UINT64_MAX:
            self._buckets[index] = count + 1

        if self._state[0] < UINT64_MAX:
            self._state[0] += 1

        total = self._state[1]
        self._state[1] = (
            UINT64_MAX
            if value > UINT64_MAX - total
            else total + value
        )

        if value < self._state[2]:
            self._state[2] = value

        if value > self._state[3]:
            self._state[3] = value

    def bucket_count(self, index: int) -> int:
        if (
            type(index) is not int
            or not 0 <= index < HISTOGRAM_BUCKETS
        ):
            raise IndexError(
                "histogram bucket index must be from 0 through 64"
            )
        return self._buckets[index]

    def quantile(
        self,
        numerator: int,
        denominator: int = 100,
    ) -> int:
        """Return a bucket upper bound rather than an exact percentile."""
        if (
            type(numerator) is not int
            or type(denominator) is not int
            or denominator <= 0
            or not 0 <= numerator <= denominator
        ):
            raise ValueError("invalid quantile fraction")

        count = self.count

        if not count:
            return 0

        if not numerator:
            return self.minimum

        rank = (
            count * numerator + denominator - 1
        ) // denominator
        cumulative = 0

        for index in range(HISTOGRAM_BUCKETS):
            cumulative += self._buckets[index]

            if cumulative >= rank:
                return min(
                    (1 << index) - 1,
                    self.maximum,
                )

        return self.maximum

    def reset(self) -> None:
        for index in range(HISTOGRAM_BUCKETS):
            self._buckets[index] = 0

        self._state[0] = 0
        self._state[1] = 0
        self._state[2] = UINT64_MAX
        self._state[3] = 0

    def write_to(
        self,
        buffer: TextIO,
        prefix: str,
        *,
        include_buckets: bool = False,
    ) -> None:
        buffer.write(f"{prefix}.count={self.count}\n")
        buffer.write(f"{prefix}.sum={self.total}\n")
        buffer.write(f"{prefix}.min={self.minimum}\n")
        buffer.write(f"{prefix}.max={self.maximum}\n")
        buffer.write(
            f"{prefix}.p50_upper={self.quantile(50)}\n"
        )
        buffer.write(
            f"{prefix}.p99_upper={self.quantile(99)}\n"
        )
        buffer.write(
            f"{prefix}.p999_upper={self.quantile(999, 1000)}\n"
        )

        if include_buckets:
            cumulative = 0

            for index in range(HISTOGRAM_BUCKETS):
                cumulative += self._buckets[index]
                upper = (1 << index) - 1
                buffer.write(
                    f"{prefix}.bucket_le_{upper}={cumulative}\n"
                )


class Metrics:
    """Reactor-owned counters and histograms.

    WAL observations cross threads through a bounded deque and are applied
    here on the reactor thread. Histograms are never mutated concurrently.
    Formatting is reserved for the diagnostic path.
    """

    __slots__ = (
        "_values",
        "wal_batch_records",
        "wal_batch_bytes",
        "wal_fsync_ns",
        "loop_lag_ns",
    )

    def __init__(self) -> None:
        self._values = array("Q", [0]) * len(Metric)
        self.wal_batch_records = LogHistogram()
        self.wal_batch_bytes = LogHistogram()
        self.wal_fsync_ns = LogHistogram()
        self.loop_lag_ns = LogHistogram()

    def get(self, metric: Metric) -> int:
        return self._values[metric]

    def add(
        self,
        metric: Metric,
        amount: int = 1,
    ) -> None:
        _nonnegative(amount)
        current = self._values[metric]
        self._values[metric] = (
            UINT64_MAX
            if amount > UINT64_MAX - current
            else current + amount
        )

    def set(self, metric: Metric, value: int) -> None:
        _nonnegative(value)
        self._values[metric] = min(value, UINT64_MAX)

    def adjust(self, metric: Metric, delta: int) -> None:
        if type(delta) is not int:
            raise TypeError("gauge delta must be an integer")

        value = self._values[metric] + delta

        if value < 0:
            raise ValueError("gauge would become negative")

        self._values[metric] = min(value, UINT64_MAX)

    def opened(self) -> None:
        self.add(Metric.ACCEPTED)
        self.add(Metric.CONNECTIONS)
        current = self.get(Metric.CONNECTIONS)

        if current > self.get(Metric.CONNECTIONS_PEAK):
            self.set(Metric.CONNECTIONS_PEAK, current)

    def closed(self) -> None:
        self.adjust(Metric.CONNECTIONS, -1)
        self.add(Metric.CLOSED)

    def observe_wal_batch(
        self,
        records: int,
        byte_count: int,
        fsync_ns: int,
        last_lsn: int,
    ) -> None:
        self.wal_batch_records.observe(records)
        self.wal_batch_bytes.observe(byte_count)
        self.wal_fsync_ns.observe(fsync_ns)
        self.add(Metric.WAL_BATCHES)
        self.add(Metric.WAL_RECORDS, records)
        self.add(Metric.WAL_BYTES, byte_count)
        self.set(Metric.WAL_DURABLE_LSN, last_lsn)

    def observe_loop_lag(
        self,
        expected_ns: int,
        actual_ns: int,
    ) -> None:
        _nonnegative(expected_ns)
        _nonnegative(actual_ns)
        self.loop_lag_ns.observe(
            max(0, actual_ns - expected_ns)
        )

    def write_to(
        self,
        buffer: TextIO,
        *,
        include_buckets: bool = False,
    ) -> None:
        for index, name in enumerate(_NAMES):
            buffer.write(
                f"{name}={self._values[index]}\n"
            )

        for name, histogram in (
            ("wal.batch_records", self.wal_batch_records),
            ("wal.batch_bytes", self.wal_batch_bytes),
            ("wal.fsync_ns", self.wal_fsync_ns),
            ("loop.lag_ns", self.loop_lag_ns),
        ):
            histogram.write_to(
                buffer,
                name,
                include_buckets=include_buckets,
            )

    def render(
        self,
        *,
        include_buckets: bool = False,
    ) -> str:
        buffer = StringIO()
        self.write_to(
            buffer,
            include_buckets=include_buckets,
        )
        return buffer.getvalue()