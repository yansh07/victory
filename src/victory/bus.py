"""Cluster delivery contract and deterministic in-process transport."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections import deque
from dataclasses import dataclass
from enum import IntEnum
from types import TracebackType

from ..protocol.codec import (
    Deliver,
    Join,
    decode_payload,
    encode_payload,
    unpack_str,
    unpack_u32,
)
from ..protocol.frame import (
    MAX_PAYLOAD,
    Frame,
    FrameType,
    ProtocolError,
)

BUS_VERSION = 1
CHANNEL_PREFIX = b"chat:room:"


class BusState(IntEnum):
    NEW = 1
    INITIALIZED = 2
    CLOSED = 3


@dataclass(frozen=True, slots=True)
class BusMessage:
    room: str
    deliver_payload: bytes
    deliver: Deliver

    @property
    def origin_node(self) -> int:
        return self.deliver.origin_node

    def to_frame(self) -> Frame:
        return Frame(
            FrameType.DELIVER,
            0,
            self.deliver_payload,
        )


@dataclass(frozen=True, slots=True)
class BusFailure:
    operation: str
    message: str
    errno: int | None = None


def validate_room(room: str) -> None:
    encode_payload(Join(room))


def channel_for(room: str) -> bytes:
    validate_room(room)
    return CHANNEL_PREFIX + room.encode("ascii")


def room_from_channel(channel: bytes) -> str:
    if not channel.startswith(CHANNEL_PREFIX):
        raise ValueError("unexpected Redis channel prefix")

    try:
        room = channel[len(CHANNEL_PREFIX):].decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("channel room must be ASCII") from None

    validate_room(room)
    return room


def decode_delivery(
    room: str,
    deliver_payload: bytes,
) -> BusMessage:
    validate_room(room)

    if not isinstance(deliver_payload, bytes):
        raise TypeError("deliver_payload must be immutable bytes")

    if len(deliver_payload) > MAX_PAYLOAD:
        raise ValueError(
            "DELIVER payload exceeds the frame limit"
        )

    delivery = decode_payload(
        FrameType.DELIVER,
        deliver_payload,
    )
    if not isinstance(delivery, Deliver):
        raise ValueError("expected a DELIVER payload")

    if delivery.room != room:
        raise ValueError(
            "DELIVER room does not match its channel"
        )

    return BusMessage(room, deliver_payload, delivery)


class ClusterBus(ABC):
    """One loop owner; publish only after the origin record is durable.

    True from publish means accepted locally, not delivered or persisted.
    poll never blocks. An unavailable transport may drop remote delivery.
    """

    def __init__(
        self,
        node_id: int,
        *,
        max_messages: int = 4096,
        max_incoming_bytes: int = 4 * 1024 * 1024,
        max_subscriptions: int = 4096,
    ) -> None:
        if (
            isinstance(node_id, bool)
            or not isinstance(node_id, int)
            or not 0 <= node_id <= 0xFFFFFFFF
        ):
            raise ValueError(
                "node_id must be an unsigned 32-bit integer"
            )

        for limit in (
            max_messages,
            max_incoming_bytes,
            max_subscriptions,
        ):
            if (
                isinstance(limit, bool)
                or not isinstance(limit, int)
                or limit < 1
            ):
                raise ValueError(
                    "bus limits must be positive integers"
                )

        self.node_id = node_id
        self._state = BusState.NEW
        self._rooms: set[str] = set()
        self._incoming: deque[BusMessage] = deque()
        self._incoming_bytes = 0
        self._max_messages = max_messages
        self._max_incoming_bytes = max_incoming_bytes
        self._max_subscriptions = max_subscriptions
        self._errors: deque[BusFailure] = deque(maxlen=64)

        self.self_echo_drops = 0
        self.invalid_messages = 0
        self.overflow_drops = 0
        self.publication_drops = 0

    @property
    def state(self) -> BusState:
        return self._state

    @property
    def ready(self) -> bool:
        return self._state == BusState.INITIALIZED

    @property
    def subscriptions(self) -> frozenset[str]:
        return frozenset(self._rooms)

    @property
    def pending_messages(self) -> int:
        return len(self._incoming)

    @property
    def incoming_bytes(self) -> int:
        return self._incoming_bytes

    def _require_open(self) -> None:
        if self._state == BusState.CLOSED:
            raise RuntimeError("cluster bus is closed")

    def _record_error(
        self,
        operation: str,
        message: str,
        error_number: int | None = None,
    ) -> None:
        self._errors.append(
            BusFailure(
                operation,
                message[:512],
                error_number,
            )
        )

    def drain_errors(self) -> list[BusFailure]:
        errors = list(self._errors)
        self._errors.clear()
        return errors

    def _publication(
        self,
        room: str,
        payload: bytes,
    ) -> BusMessage:
        message = decode_delivery(room, payload)
        if message.origin_node != self.node_id:
            raise ValueError(
                "a node may only publish its own durable deliveries"
            )
        return message

    def _offer(self, message: BusMessage) -> bool:
        if (
            self._state == BusState.CLOSED
            or message.room not in self._rooms
        ):
            return False

        if message.origin_node == self.node_id:
            self.self_echo_drops += 1
            return False

        size = len(message.deliver_payload)
        if (
            len(self._incoming) >= self._max_messages
            or size
            > self._max_incoming_bytes - self._incoming_bytes
        ):
            self.overflow_drops += 1
            self._record_error(
                "receive",
                "incoming bus queue limit reached",
            )
            return False

        self._incoming.append(message)
        self._incoming_bytes += size
        return True

    def _receive_envelope(
        self,
        channel: bytes,
        envelope: bytes,
    ) -> None:
        try:
            room = room_from_channel(channel)
            if room not in self._rooms:
                return

            if not envelope or envelope[0] != BUS_VERSION:
                raise ValueError(
                    "unsupported or missing cluster bus version"
                )

            if len(envelope) - 1 > MAX_PAYLOAD:
                raise ValueError(
                    "cluster payload exceeds the frame limit"
                )

            with memoryview(envelope) as raw:
                with raw[1:] as payload:
                    embedded_room, offset = unpack_str(
                        payload,
                        max_length=64,
                    )
                    origin_node, _offset = unpack_u32(
                        payload,
                        offset,
                    )

                    if embedded_room != room:
                        raise ValueError(
                            "cluster room does not match its channel"
                        )

                    # Drop local echoes before copying the message body.
                    if origin_node == self.node_id:
                        self.self_echo_drops += 1
                        return

                    message = decode_delivery(
                        room,
                        bytes(payload),
                    )

            self._offer(message)

        except (ProtocolError, ValueError, TypeError) as error:
            self.invalid_messages += 1
            self._record_error("decode", str(error))

    def poll(self) -> list[BusMessage]:
        messages: list[BusMessage] = []

        while self._incoming:
            message = self._incoming.popleft()
            self._incoming_bytes -= len(
                message.deliver_payload
            )
            if message.room in self._rooms:
                messages.append(message)

        return messages

    def _finish_close(self) -> None:
        self._state = BusState.CLOSED
        self._rooms.clear()
        self._incoming.clear()
        self._incoming_bytes = 0

    def __enter__(self) -> ClusterBus:
        self.initialize()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    @abstractmethod
    def initialize(self) -> None:
        """Start transport work without waiting for network completion."""

    @abstractmethod
    def publish(
        self,
        room: str,
        deliver_payload: bytes,
    ) -> bool:
        """Accept a durable local DELIVER payload or return False."""

    @abstractmethod
    def subscribe(self, room: str) -> bool:
        """Remember desired membership and arrange subscription."""

    @abstractmethod
    def unsubscribe(self, room: str) -> bool:
        """Remove desired membership without waiting for a reply."""

    @abstractmethod
    def close(self) -> None:
        """Release owned resources; repeated calls must be safe."""


class InProcessHub:
    def __init__(self) -> None:
        self._nodes: dict[int, InProcessBus] = {}
        self._subscribers: dict[str, set[int]] = {}

    def _attach(self, bus: InProcessBus) -> None:
        existing = self._nodes.get(bus.node_id)
        if existing is not None and existing is not bus:
            raise ValueError(
                "node_id must be unique within an in-process hub"
            )
        self._nodes[bus.node_id] = bus

    def _subscribe(self, node_id: int, room: str) -> None:
        self._subscribers.setdefault(room, set()).add(node_id)

    def _unsubscribe(self, node_id: int, room: str) -> None:
        subscribers = self._subscribers.get(room)
        if subscribers is not None:
            subscribers.discard(node_id)
            if not subscribers:
                del self._subscribers[room]

    def _publish(self, message: BusMessage) -> None:
        for node_id in sorted(
            self._subscribers.get(message.room, ())
        ):
            self._nodes[node_id]._offer(message)

    def _detach(self, bus: InProcessBus) -> None:
        if self._nodes.get(bus.node_id) is bus:
            for room in bus.subscriptions:
                self._unsubscribe(bus.node_id, room)
            del self._nodes[bus.node_id]

    def close(self) -> None:
        for bus in list(self._nodes.values()):
            bus.close()


class InProcessBus(ClusterBus):
    def __init__(
        self,
        node_id: int,
        hub: InProcessHub,
        *,
        max_messages: int = 4096,
        max_incoming_bytes: int = 4 * 1024 * 1024,
        max_subscriptions: int = 4096,
    ) -> None:
        super().__init__(
            node_id,
            max_messages=max_messages,
            max_incoming_bytes=max_incoming_bytes,
            max_subscriptions=max_subscriptions,
        )
        self._hub = hub
        self.initialize()

    def initialize(self) -> None:
        self._require_open()
        if self._state == BusState.NEW:
            self._hub._attach(self)
            self._state = BusState.INITIALIZED

    def publish(
        self,
        room: str,
        deliver_payload: bytes,
    ) -> bool:
        self._require_open()
        self._hub._publish(
            self._publication(room, deliver_payload)
        )
        return True

    def subscribe(self, room: str) -> bool:
        self._require_open()
        validate_room(room)

        if room in self._rooms:
            return True

        if len(self._rooms) >= self._max_subscriptions:
            self._record_error(
                "subscribe",
                "subscription limit reached",
            )
            return False

        self._rooms.add(room)
        self._hub._subscribe(self.node_id, room)
        return True

    def unsubscribe(self, room: str) -> bool:
        self._require_open()
        validate_room(room)

        if room not in self._rooms:
            return False

        self._rooms.remove(room)
        self._hub._unsubscribe(self.node_id, room)
        return True

    def close(self) -> None:
        if self._state != BusState.CLOSED:
            self._hub._detach(self)
            self._finish_close()