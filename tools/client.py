#!/usr/bin/env python3
from __future__ import annotations

import argparse
import errno
import math
import os
import re
import secrets
import select
import signal
import socket
import sys
import time
from collections import deque
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from types import FrameType

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from victory.protocol.codec import (
    pack_blob,
    pack_str,
    pack_u8,
    pack_u32,
    pack_u64,
    require_consumed,
    unpack_blob,
    unpack_str,
    unpack_u8,
    unpack_u16,
    unpack_u32,
    unpack_u64,
)
from victory.protocol.decoder import FrameDecoder
from victory.protocol.frame import Frame, ProtocolError

MAX_PAYLOAD = 65536
MAX_BODY = 16384
IO_BUDGET = 65536
QUEUE_LIMIT = 256 * 1024
MAX_PENDING = 128
UINT32_MAX = (1 << 32) - 1
UINT64_MAX = (1 << 64) - 1
ROOM_PATTERN = re.compile(r"[A-Za-z0-9._:-]{1,64}\Z")
USER_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
_STOP_COUNT = 0


class Kind(IntEnum):
    HELLO = 1
    JOIN = 2
    MSG = 4
    PING = 5
    PONG = 6
    ACK = 7
    ERROR = 8
    SHUTDOWN = 9
    DELIVER = 10
    HELLO_OK = 11


class State(IntEnum):
    WAIT_HELLO = 0
    WAIT_JOIN = 1
    ACTIVE = 2
    DRAINING = 3
    CLOSED = 4


class ClientError(RuntimeError):
    """A client transport, lifecycle, or peer contract failed."""


@dataclass(slots=True)
class WriteChunk:
    data: memoryview
    kind: int
    request_id: int
    offset: int = 0


@dataclass(slots=True)
class PendingMessage:
    message_id: int
    deadline: float


def terminal_text(text: str) -> str:
    # Message bodies are opaque bytes; terminal escape sequences are untrusted.
    return "".join(
        char if char.isprintable() else ascii(char)[1:-1]
        for char in text
    )


def notice(text: str) -> None:
    print(terminal_text(text), file=sys.stderr, flush=True)


def request_stop(signum: int, frame: FrameType | None) -> None:
    global _STOP_COUNT
    _STOP_COUNT += 1


def connect_socket(host: str, port: int, timeout: float) -> socket.socket:
    deadline = time.monotonic() + timeout
    addresses = socket.getaddrinfo(
        host, port, socket.AF_UNSPEC, socket.SOCK_STREAM
    )
    last_error: OSError | None = None

    for family, socktype, protocol, canonical_name, address in addresses:
        if _STOP_COUNT:
            raise KeyboardInterrupt

        sock = socket.socket(family, socktype, protocol)
        sock.setblocking(False)

        try:
            error = sock.connect_ex(address)
            if error not in (
                0,
                errno.EINPROGRESS,
                errno.EWOULDBLOCK,
                errno.EALREADY,
                errno.EINTR,
            ):
                raise OSError(error, os.strerror(error))

            while error:
                if _STOP_COUNT:
                    raise KeyboardInterrupt

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("connection deadline expired")

                try:
                    _, writable, exceptional = select.select(
                        [], [sock], [sock], min(remaining, 0.25)
                    )
                except InterruptedError:
                    continue

                if not writable and not exceptional:
                    continue

                error = sock.getsockopt(
                    socket.SOL_SOCKET, socket.SO_ERROR
                )
                if error:
                    raise OSError(error, os.strerror(error))

            return sock

        except OSError as exc:
            last_error = exc
            sock.close()
            if time.monotonic() >= deadline:
                break

        except BaseException:
            sock.close()
            raise

    if last_error is not None:
        raise last_error

    raise ClientError("host has no usable TCP address")


class TerminalInput:
    def __init__(self, fd: int) -> None:
        self.fd = fd
        self.buffer = bytearray()
        self.offset = 0
        self.eof = False
        self.discarding = False

    def read(self) -> None:
        try:
            data = os.read(self.fd, 4096)
        except (BlockingIOError, InterruptedError):
            return

        if data:
            self.buffer.extend(data)
        else:
            self.eof = True

    def pop_line(self) -> bytes | None:
        while True:
            end = self.buffer.find(b"\n", self.offset)

            if end < 0 and not self.eof:
                if (
                    self.discarding
                    or len(self.buffer) - self.offset > MAX_BODY + 1
                ):
                    if not self.discarding:
                        notice(
                            f"input line exceeds {MAX_BODY} bytes; discarded"
                        )
                    self.discarding = True
                    self.buffer.clear()
                    self.offset = 0
                return None

            if end < 0:
                if self.offset == len(self.buffer):
                    return None
                end = len(self.buffer)
                next_offset = end
            else:
                next_offset = end + 1

            if self.discarding:
                self.discarding = False
                self.offset = next_offset
                self._compact()
                continue

            line = bytes(memoryview(self.buffer)[self.offset:end])
            self.offset = next_offset
            self._compact()

            if line.endswith(b"\r"):
                line = line[:-1]

            if len(line) > MAX_BODY:
                notice(f"input line exceeds {MAX_BODY} bytes; discarded")
                continue

            return line

    def _compact(self) -> None:
        if self.offset == len(self.buffer):
            self.buffer.clear()
            self.offset = 0
        elif self.offset > len(self.buffer) // 2:
            del self.buffer[:self.offset]
            self.offset = 0

    @property
    def finished(self) -> bool:
        return self.eof and self.offset == len(self.buffer)


class ChatClient:
    def __init__(
        self,
        sock: socket.socket,
        args: argparse.Namespace,
        stdin_fd: int,
    ) -> None:
        self.sock = sock
        self.args = args
        self.input = TerminalInput(stdin_fd)
        self.decoder = FrameDecoder()
        self.scratch = bytearray(IO_BUDGET)
        self.outgoing: deque[WriteChunk] = deque()
        self.queued_bytes = 0
        self.pending: dict[int, PendingMessage] = {}
        self.next_request_id = 16

        # Restarting must not reset a user's idempotency keys to one.
        self.next_message_id = secrets.randbits(63) + 1

        self.state = State.WAIT_HELLO
        self.max_payload = MAX_PAYLOAD
        self.heartbeat = args.heartbeat_ms / 1000.0
        self.last_received = time.monotonic()
        self.last_sent = self.last_received
        self.phase_deadline = (
            self.last_received + args.handshake_timeout
        )
        self.close_deadline: float | None = None
        self.ping_nonce: int | None = None
        self.server_closing = False
        self.shutdown_sent = False
        self.exit_status = 0

        hello = (
            pack_u32(args.heartbeat_ms)
            + pack_str(args.user, max_length=64)
            + pack_str(args.token, max_length=256)
        )
        self.queue(Kind.HELLO, 1, hello)

    def queue(
        self, kind: int, request_id: int, payload: bytes
    ) -> None:
        if len(payload) > self.max_payload:
            raise ClientError(
                "payload exceeds the negotiated frame limit"
            )

        packet = Frame(
            type=int(kind),
            request_id=request_id,
            payload=payload,
        ).to_bytes()

        if self.queued_bytes + len(packet) > QUEUE_LIMIT + MAX_PAYLOAD:
            raise ClientError("client outbound queue limit exceeded")

        self.outgoing.append(
            WriteChunk(memoryview(packet), kind, request_id)
        )
        self.queued_bytes += len(packet)

    def flush(self) -> None:
        budget = IO_BUDGET

        while self.outgoing and budget:
            head = self.outgoing[0]

            try:
                count = self.sock.send(
                    head.data[head.offset:head.offset + budget]
                )
            except InterruptedError:
                continue
            except BlockingIOError:
                return

            if count <= 0:
                raise ClientError("socket send made no progress")

            head.offset += count
            self.queued_bytes -= count
            budget -= count

            if head.offset == len(head.data):
                self.outgoing.popleft()
                self.last_sent = time.monotonic()

    def read(self) -> None:
        budget = IO_BUDGET

        while budget:
            try:
                count = self.sock.recv_into(self.scratch, budget)
            except InterruptedError:
                continue
            except BlockingIOError:
                return

            if not count:
                if self.decoder.buffered_bytes:
                    raise ClientError(
                        "server closed in the middle of a frame"
                    )
                if self.state != State.DRAINING:
                    raise ClientError(
                        "server disconnected unexpectedly"
                    )
                self.state = State.CLOSED
                return

            budget -= count

            # No view of reusable scratch survives the decoder call.
            with memoryview(self.scratch)[:count] as view:
                frames = self.decoder.feed(bytes(view))

            for frame in frames:
                self.handle(frame)
                self.last_received = time.monotonic()

            for error in self.decoder.drain_errors():
                if self.state == State.WAIT_HELLO:
                    raise ClientError(
                        f"invalid handshake frame: {error}"
                    )
                notice(f"ignored unknown server frame: {error}")

    def handle(self, frame: Frame) -> None:
        kind = int(frame.type)
        data = frame.payload

        if kind == Kind.ERROR:
            code, offset = unpack_u16(data)
            fatal, offset = unpack_u8(data, offset)
            message, offset = unpack_str(
                data, offset, max_length=256
            )
            require_consumed(data, offset)

            if fatal not in (0, 1):
                raise ClientError("invalid ERROR fatal flag")

            rejected = self.pending.pop(frame.request_id, None)
            correlation = (
                f", message_id={rejected.message_id}"
                if rejected else ""
            )
            notice(
                f"server ERROR {code}, request={frame.request_id}"
                f"{correlation}: {message}"
            )
            self.exit_status = 1

            if self.state in (State.WAIT_HELLO, State.WAIT_JOIN):
                raise ClientError(
                    "server rejected session initialization"
                )

            if fatal:
                self.state = State.DRAINING
                self.server_closing = True
                self.outgoing.clear()
                self.queued_bytes = 0
                self._set_close_deadline(
                    self.args.shutdown_timeout
                )
            elif code == 17:
                self.begin_close()

            return

        if kind == Kind.HELLO_OK:
            if (
                self.state != State.WAIT_HELLO
                or frame.request_id != 1
            ):
                raise ClientError("unexpected HELLO_OK")

            session_id, offset = unpack_u64(data)
            node_id, offset = unpack_u32(data, offset)
            heartbeat_ms, offset = unpack_u32(data, offset)
            max_payload, offset = unpack_u32(data, offset)
            require_consumed(data, offset)

            if not 1000 <= heartbeat_ms <= 60000:
                raise ClientError("invalid negotiated heartbeat")
            if not 1 <= max_payload <= MAX_PAYLOAD:
                raise ClientError("invalid negotiated frame limit")

            self.heartbeat = heartbeat_ms / 1000.0
            self.max_payload = max_payload
            self.state = State.WAIT_JOIN
            self.phase_deadline = (
                time.monotonic() + self.args.handshake_timeout
            )
            self.queue(
                Kind.JOIN,
                2,
                pack_str(self.args.room, max_length=64),
            )
            notice(
                f"authenticated: node={node_id}, session={session_id}"
            )
            return

        if self.state == State.WAIT_HELLO:
            raise ClientError("expected HELLO_OK")

        if kind == Kind.ACK:
            acked_type, offset = unpack_u8(data)
            durable, offset = unpack_u8(data, offset)
            seq, offset = unpack_u64(data, offset)
            require_consumed(data, offset)

            if (
                self.state == State.WAIT_JOIN
                and frame.request_id == 2
            ):
                if (acked_type, durable, seq) != (Kind.JOIN, 0, 0):
                    raise ClientError(
                        "invalid JOIN acknowledgment"
                    )
                self.state = State.ACTIVE
                notice(
                    f"joined {self.args.room}; enter messages, "
                    "/quit, or EOF to leave"
                )
                return

            if acked_type != Kind.MSG or durable != 1 or seq == 0:
                raise ClientError(
                    "invalid durable MSG acknowledgment"
                )

            if self.pending.pop(frame.request_id, None) is None:
                raise ClientError(
                    "ACK has no outstanding request"
                )
            return

        if kind == Kind.DELIVER:
            if frame.request_id != 0:
                raise ClientError(
                    "DELIVER must be server initiated"
                )

            room, offset = unpack_str(data, max_length=64)
            origin_node, offset = unpack_u32(data, offset)
            seq, offset = unpack_u64(data, offset)
            sender, offset = unpack_str(
                data, offset, max_length=64
            )
            client_msg_id, offset = unpack_u64(data, offset)
            body, offset = unpack_blob(
                data, offset, max_length=MAX_BODY
            )
            require_consumed(data, offset)

            if (
                not ROOM_PATTERN.fullmatch(room)
                or not USER_PATTERN.fullmatch(sender)
                or not seq
                or room != self.args.room
            ):
                raise ClientError("invalid DELIVER metadata")

            text = terminal_text(
                body.decode("utf-8", errors="backslashreplace")
            )
            print(f"[{room}] {sender}: {text}", flush=True)
            return

        if kind in (Kind.PING, Kind.PONG):
            nonce, offset = unpack_u64(data)
            require_consumed(data, offset)

            if kind == Kind.PING:
                self.queue(
                    Kind.PONG, frame.request_id, pack_u64(nonce)
                )
            elif frame.request_id == 3 and nonce == self.ping_nonce:
                self.ping_nonce = None
            else:
                raise ClientError("unexpected PONG")
            return

        if kind == Kind.SHUTDOWN:
            reason, offset = unpack_u8(data)
            deadline_ms, offset = unpack_u32(data, offset)
            require_consumed(data, offset)

            if reason != 0 or frame.request_id != 0:
                raise ClientError("invalid server SHUTDOWN")

            self.state = State.DRAINING
            self.server_closing = True
            self._set_close_deadline(
                min(
                    deadline_ms / 1000.0,
                    self.args.shutdown_timeout,
                )
            )
            self._cancel_unsent_messages()
            notice(
                f"server shutting down; drain deadline={deadline_ms} ms"
            )
            return

        raise ClientError(f"unexpected server frame type {kind}")

    def _cancel_unsent_messages(self) -> None:
        retained: deque[WriteChunk] = deque()

        for chunk in self.outgoing:
            if chunk.kind == Kind.MSG and chunk.offset == 0:
                message = self.pending.pop(
                    chunk.request_id, None
                )
                self.queued_bytes -= len(chunk.data)

                if message is not None:
                    self.exit_status = 1
                    notice(
                        f"message_id={message.message_id} was not sent"
                    )
            else:
                # Finish a started frame to preserve stream alignment.
                retained.append(chunk)

        self.outgoing = retained

    def _set_close_deadline(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        if (
            self.close_deadline is None
            or deadline < self.close_deadline
        ):
            self.close_deadline = deadline

    def begin_close(self) -> None:
        if self.state == State.ACTIVE:
            self.state = State.DRAINING
            self._set_close_deadline(
                self.args.shutdown_timeout
            )
        elif self.state in (State.WAIT_HELLO, State.WAIT_JOIN):
            self.state = State.CLOSED

    def can_accept_input(self) -> bool:
        return (
            self.state == State.ACTIVE
            and len(self.pending) < MAX_PENDING
            and self.queued_bytes < QUEUE_LIMIT
        )

    def pump_input(self) -> None:
        while self.can_accept_input():
            line = self.input.pop_line()

            if line is None:
                if self.input.finished:
                    self.begin_close()
                return

            if line == b"/quit":
                self.begin_close()
                return

            try:
                line.decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                notice("input is not valid UTF-8; line discarded")
                continue

            if (
                self.next_request_id > UINT32_MAX
                or self.next_message_id > UINT64_MAX
            ):
                raise ClientError(
                    "local correlation identifier space exhausted"
                )

            request_id = self.next_request_id
            message_id = self.next_message_id
            payload = (
                pack_str(self.args.room, max_length=64)
                + pack_u64(message_id)
                + pack_blob(line, max_length=MAX_BODY)
            )

            if len(payload) > self.max_payload:
                notice(
                    "message exceeds the negotiated payload limit; discarded"
                )
                continue

            self.queue(Kind.MSG, request_id, payload)
            self.pending[request_id] = PendingMessage(
                message_id,
                time.monotonic() + self.args.ack_timeout,
            )
            self.next_request_id += 1
            self.next_message_id += 1

    def tick(self) -> None:
        now = time.monotonic()

        if _STOP_COUNT >= 2:
            self.exit_status = 130
            self.state = State.CLOSED
            return

        if _STOP_COUNT:
            self.begin_close()

        if self.state == State.CLOSED:
            return

        if self.state in (State.WAIT_HELLO, State.WAIT_JOIN):
            if now >= self.phase_deadline:
                raise ClientError(
                    "handshake or JOIN deadline expired"
                )
            return

        if (
            self.close_deadline is not None
            and now >= self.close_deadline
        ):
            if (
                self.pending
                or self.outgoing
                or not self.server_closing
            ):
                self.exit_status = 1
                notice("connection drain deadline expired")
            self.state = State.CLOSED
            return

        if now - self.last_received >= self.heartbeat * 3:
            raise ClientError("server liveness deadline expired")

        if any(
            now >= item.deadline
            for item in self.pending.values()
        ):
            raise ClientError(
                "MSG acknowledgment deadline expired"
            )

        if (
            not self.server_closing
            and self.ping_nonce is None
            and now - self.last_sent >= self.heartbeat / 2
        ):
            self.ping_nonce = time.monotonic_ns() & UINT64_MAX
            self.queue(
                Kind.PING, 3, pack_u64(self.ping_nonce)
            )

        if (
            self.state == State.DRAINING
            and not self.server_closing
            and not self.shutdown_sent
            and not self.pending
            and not self.outgoing
        ):
            self.queue(
                Kind.SHUTDOWN,
                4,
                pack_u8(1) + pack_u32(0),
            )
            self.shutdown_sent = True

    def step(self) -> None:
        self.tick()
        if self.state == State.CLOSED:
            return

        self.pump_input()

        readable: list[int | socket.socket] = [self.sock]
        if self.can_accept_input() and not self.input.eof:
            readable.append(self.input.fd)

        writable = [self.sock] if self.outgoing else []
        deadlines = [time.monotonic() + 0.25]

        if self.state in (State.WAIT_HELLO, State.WAIT_JOIN):
            deadlines.append(self.phase_deadline)
        else:
            deadlines.append(
                self.last_received + self.heartbeat * 3
            )
            if self.ping_nonce is None and not self.server_closing:
                deadlines.append(
                    self.last_sent + self.heartbeat / 2
                )

        if self.close_deadline is not None:
            deadlines.append(self.close_deadline)

        deadlines.extend(
            item.deadline for item in self.pending.values()
        )
        timeout = max(
            0.0, min(deadlines) - time.monotonic()
        )

        try:
            reads, writes, errors = select.select(
                readable,
                writable,
                [self.sock],
                timeout,
            )
        except InterruptedError:
            return

        if errors:
            error = self.sock.getsockopt(
                socket.SOL_SOCKET, socket.SO_ERROR
            )
            raise OSError(
                error or errno.ECONNRESET,
                "socket exception",
            )

        # Process SHUTDOWN before more terminal input or socket writes.
        if self.sock in reads:
            self.read()

        if self.state == State.CLOSED:
            return

        if self.sock in writes and self.outgoing:
            self.flush()

        if self.input.fd in reads and self.can_accept_input():
            self.input.read()
            self.pump_input()

    def run(self) -> int:
        original_blocking = os.get_blocking(self.input.fd)

        try:
            os.set_blocking(self.input.fd, False)
            while self.state != State.CLOSED:
                self.step()
        finally:
            self.sock.close()
            os.set_blocking(
                self.input.fd, original_blocking
            )

            if self.pending:
                if self.exit_status == 0:
                    self.exit_status = 1

                for request_id, item in self.pending.items():
                    notice(
                        f"UNCONFIRMED request={request_id}, "
                        f"client_msg_id={item.message_id}; "
                        "durability is unknown"
                    )

            self.outgoing.clear()

        return self.exit_status


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Interactive Victory protocol client"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--user", required=True)
    parser.add_argument(
        "--token", default=os.environ.get("VICTORY_TOKEN")
    )
    parser.add_argument("--room", default="general")
    parser.add_argument(
        "--heartbeat-ms", type=int, default=10000
    )
    parser.add_argument(
        "--connect-timeout", type=float, default=5.0
    )
    parser.add_argument(
        "--handshake-timeout", type=float, default=5.0
    )
    parser.add_argument(
        "--ack-timeout", type=float, default=30.0
    )
    parser.add_argument(
        "--shutdown-timeout", type=float, default=5.0
    )
    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        parser.error("port must be within 1..65535")

    if not USER_PATTERN.fullmatch(args.user):
        parser.error(
            "user must contain 1..64 characters from [A-Za-z0-9._-]"
        )

    if not ROOM_PATTERN.fullmatch(args.room):
        parser.error(
            "room must contain 1..64 characters from [A-Za-z0-9._:-]"
        )

    if args.token is None:
        parser.error("provide --token or VICTORY_TOKEN")

    if (
        len(args.token.encode("utf-8")) > 256
        or "\x00" in args.token
    ):
        parser.error(
            "token must contain at most 256 UTF-8 bytes and no NUL"
        )

    if not 1000 <= args.heartbeat_ms <= 60000:
        parser.error("heartbeat-ms must be within 1000..60000")

    for name in (
        "connect_timeout",
        "handshake_timeout",
        "ack_timeout",
        "shutdown_timeout",
    ):
        value = getattr(args, name)
        if not math.isfinite(value) or not 0 < value <= 3600:
            parser.error(
                f"{name.replace('_', '-')} must be within (0, 3600]"
            )

    return args


def main() -> int:
    global _STOP_COUNT
    _STOP_COUNT = 0
    args = parse_args()

    old_handlers = {
        signum: signal.getsignal(signum)
        for signum in (signal.SIGINT, signal.SIGTERM)
    }
    sock: socket.socket | None = None

    try:
        for signum in old_handlers:
            signal.signal(signum, request_stop)

        stdin_fd = sys.stdin.fileno()
        sock = connect_socket(
            args.host, args.port, args.connect_timeout
        )
        return ChatClient(sock, args, stdin_fd).run()

    except KeyboardInterrupt:
        return 130

    except (OSError, ValueError, ProtocolError, ClientError) as exc:
        notice(f"client error: {exc}")
        return 1

    finally:
        if sock is not None:
            sock.close()

        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)


if __name__ == "__main__":
    raise SystemExit(main())