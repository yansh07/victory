#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import secrets
import selectors
import socket
import struct
import sys
import time

if __package__:
    from .loadgen import (
        MAX_BODY,
        READ_BUDGET,
        ROOM_PATTERN,
        ProtocolClient,
        WireError,
        WireFrame,
        authentication_token,
        decode_ack,
        encode_message,
        handshake,
        resolve_address,
    )
else:
    from loadgen import (
        MAX_BODY,
        READ_BUDGET,
        ROOM_PATTERN,
        ProtocolClient,
        WireError,
        WireFrame,
        authentication_token,
        decode_ack,
        encode_message,
        handshake,
        resolve_address,
    )


def _stats(frame: WireFrame) -> dict[str, int]:
    if frame.kind != 13 or frame.request_id != 4:
        raise WireError("unexpected STATS response")

    values: dict[str, int] = {}
    for line in frame.payload.decode("utf-8").splitlines():
        key, separator, value = line.partition("=")
        if not separator or key in values:
            raise WireError("malformed STATS output")

        try:
            parsed = int(value)
        except ValueError:
            continue

        if parsed < 0:
            raise WireError("negative STATS counter")
        values[key] = parsed

    required = (
        "connections.current",
        "backpressure.slow_consumers_total",
    )
    if any(key not in values for key in required):
        raise WireError(
            "node does not export the required backpressure metrics"
        )
    return values


def _events(
    peer: ProtocolClient,
    selector: selectors.BaseSelector,
    scratch: bytearray,
    timeout: float,
) -> list[WireFrame]:
    selector.modify(peer.socket, peer.interest)
    frames: list[WireFrame] = []

    for key, mask in selector.select(max(0.0, timeout)):
        if mask & selectors.EVENT_WRITE:
            peer.flush()
        if mask & selectors.EVENT_READ:
            frames.extend(peer.read_frames(scratch))

    if peer.eof:
        raise WireError("the healthy publisher connection closed")

    return frames


def _baseline(
    peer: ProtocolClient,
    selector: selectors.BaseSelector,
    scratch: bytearray,
) -> dict[str, int]:
    deadline = time.monotonic() + 5.0
    waiting = False
    next_request = 0.0
    last: dict[str, int] = {}

    while time.monotonic() < deadline:
        now = time.monotonic()
        if not waiting and now >= next_request:
            peer.queue_frame(12, 4, b"")
            waiting = True

        for frame in _events(
            peer, selector, scratch, min(0.1, deadline - now)
        ):
            if frame.kind == 13:
                last = _stats(frame)
                waiting = False
                next_request = time.monotonic() + 0.1
                if last["connections.current"] == 2:
                    return last
            elif not peer.handle_control(frame):
                raise WireError("unexpected baseline response")

    raise WireError(
        "use an isolated direct-node endpoint: expected only "
        "the stalled connection and its healthy publisher; "
        f"last metrics={last}"
    )


def run(
    args: argparse.Namespace, token: str
) -> dict[str, object]:
    suffix = secrets.token_hex(6)
    room = args.room or "slow_" + suffix
    if not ROOM_PATTERN.fullmatch(room):
        raise ValueError("invalid room")

    target = resolve_address(args.host, args.port)
    observer = resolve_address(
        args.observer_host or args.host,
        args.observer_port or args.port,
    )
    stalled: ProtocolClient | None = None
    publisher: ProtocolClient | None = None

    try:
        stalled = handshake(
            target,
            "slow_" + suffix,
            token,
            room,
            timeout=args.connect_timeout,
            heartbeat_ms=60000,
            receive_buffer=1024,
        )
        frozen_read_calls = stalled.read_calls

        # Never register this socket for READ again, including MSG_PEEK.
        # A FIN can remain behind queued data when its receive window closes.
        publisher = handshake(
            observer,
            "producer_" + suffix,
            token,
            room,
            timeout=args.connect_timeout,
        )

        if publisher.node_id != stalled.node_id:
            raise WireError(
                "observer reached another node; use a direct node "
                "port or --observer-host/--observer-port for the "
                "stalled connection's node"
            )

        if args.timeout >= stalled.heartbeat_ms * 3 / 1000.0 - 0.5:
            raise WireError(
                "test timeout must be below the negotiated idle timeout"
            )

        scratch = bytearray(READ_BUDGET)

        with selectors.DefaultSelector() as selector:
            selector.register(
                publisher.socket, publisher.interest
            )
            baseline = _baseline(publisher, selector, scratch)
            initial_evictions = baseline[
                "backpressure.slow_consumers_total"
            ]
            body = b"s" * args.body_bytes
            pending: set[int] = set()
            sent = 0
            acknowledged = 0
            stats_waiting = False
            next_stats = time.monotonic()
            deadline = time.monotonic() + args.timeout
            latest = baseline
            evicted = False
            verification_nonce: int | None = None
            healthy_after_eviction = False

            while time.monotonic() < deadline:
                now = time.monotonic()

                if not evicted:
                    while (
                        len(pending) < args.max_inflight
                        and (sent + 1) * len(body) <= args.max_bytes
                    ):
                        message_id = sent + 1
                        request_id = 1000 + message_id
                        publisher.queue_frame(
                            4,
                            request_id,
                            encode_message(room, message_id, body),
                        )
                        pending.add(request_id)
                        sent += 1

                publisher.heartbeat(time.monotonic_ns())

                if (
                    not stats_waiting
                    and now >= next_stats
                    and verification_nonce is None
                ):
                    publisher.queue_frame(12, 4, b"")
                    stats_waiting = True
                    next_stats = now + 0.25

                if (
                    evicted
                    and not pending
                    and not publisher.outgoing
                    and publisher.pending_ping is None
                    and verification_nonce is None
                ):
                    verification_nonce = time.monotonic_ns()
                    publisher.pending_ping = verification_nonce
                    publisher.queue_frame(
                        5,
                        3,
                        struct.pack("!Q", verification_nonce),
                    )

                for frame in _events(
                    publisher,
                    selector,
                    scratch,
                    min(0.05, deadline - now),
                ):
                    if frame.kind == 13:
                        if not stats_waiting:
                            raise WireError(
                                "unsolicited STATS response"
                            )
                        latest = _stats(frame)
                        stats_waiting = False
                        evicted = evicted or (
                            latest[
                                "backpressure.slow_consumers_total"
                            ] > initial_evictions
                            and latest["connections.current"] == 1
                        )

                    elif frame.kind == 7:
                        kind, durable, seq = decode_ack(frame)
                        if (
                            kind != 4
                            or durable != 1
                            or not seq
                            or frame.request_id not in pending
                        ):
                            raise WireError(
                                "invalid publisher ACK"
                            )
                        pending.remove(frame.request_id)
                        acknowledged += 1

                    else:
                        verification_response = (
                            verification_nonce is not None
                            and frame.kind == 6
                            and frame.payload == struct.pack(
                                "!Q", verification_nonce
                            )
                        )
                        if not publisher.handle_control(frame):
                            raise WireError(
                                "unexpected publisher frame"
                            )
                        if verification_response:
                            healthy_after_eviction = True

                if evicted and healthy_after_eviction and not pending:
                    break

            if not evicted or not healthy_after_eviction or pending:
                raise WireError(
                    "slow-consumer eviction was not verified "
                    "within the budget; "
                    f"sent={sent}, durable_acks={acknowledged}, "
                    f"metrics={latest}"
                )

            if stalled.read_calls != frozen_read_calls:
                raise AssertionError(
                    "the stalled connection's read path resumed"
                )

            tcp_state: int | None = None
            if hasattr(socket, "TCP_INFO"):
                try:
                    tcp_state = stalled.socket.getsockopt(
                        socket.IPPROTO_TCP,
                        socket.TCP_INFO,
                        256,
                    )[0]
                except OSError:
                    tcp_state = None

            return {
                "verified": True,
                "node_id": stalled.node_id,
                "session_id": stalled.session_id,
                "room": room,
                "messages_published": sent,
                "durable_acks": acknowledged,
                "body_bytes_published": sent * len(body),
                "slow_consumer_evictions_before": initial_evictions,
                "slow_consumer_evictions_after": latest[
                    "backpressure.slow_consumers_total"
                ],
                "stalled_read_calls_after_join": (
                    stalled.read_calls - frozen_read_calls
                ),
                "healthy_publisher_round_trip": healthy_after_eviction,
                "stalled_tcp_state": tcp_state,
                "verification": (
                    "same-node metrics, isolated connection "
                    "count, and healthy publisher PONG"
                ),
            }
    finally:
        if publisher is not None:
            publisher.close()
        if stalled is not None:
            stalled.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify Victory slow-consumer eviction without "
            "reading the stalled socket"
        )
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--port",
        type=int,
        default=9001,
        help="direct Victory node port",
    )
    parser.add_argument("--observer-host")
    parser.add_argument("--observer-port", type=int)
    parser.add_argument("--token")
    parser.add_argument("--room")
    parser.add_argument("--body-bytes", type=int, default=8192)
    parser.add_argument("--max-inflight", type=int, default=16)
    parser.add_argument(
        "--max-bytes", type=int, default=32 * 1024 * 1024
    )
    parser.add_argument("--timeout", type=float, default=25.0)
    parser.add_argument(
        "--connect-timeout", type=float, default=5.0
    )
    args = parser.parse_args()

    try:
        if (
            not 1 <= args.port <= 65535
            or (
                args.observer_port is not None
                and not 1 <= args.observer_port <= 65535
            )
        ):
            raise ValueError("invalid port")

        if (
            not 1 <= args.body_bytes <= MAX_BODY
            or not 1 <= args.max_inflight <= 32
        ):
            raise ValueError(
                "invalid body size or inflight limit"
            )

        if not args.body_bytes <= args.max_bytes <= 1024 * 1024 * 1024:
            raise ValueError(
                "max-bytes must be within one body and 1 GiB"
            )

        if any(
            not math.isfinite(value) or not 0 < value <= 120
            for value in (args.timeout, args.connect_timeout)
        ):
            raise ValueError(
                "timeouts must be finite and within (0, 120] seconds"
            )

        report = run(args, authentication_token(args.token))
        print(json.dumps(report, sort_keys=True))
        return 0

    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(
            json.dumps({
                "verified": False,
                "error": f"{type(exc).__name__}: {exc}",
            }),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())