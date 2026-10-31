#!/usr/bin/env python3
from __future__ import annotations

import argparse
import errno
import json
import math
import os
import random
import re
import selectors
import signal
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

if __package__:
    from .loadgen import (
        FrameStream,
        WireError,
        decode_error,
        resolve_address,
    )
else:
    from loadgen import (
        FrameStream,
        WireError,
        decode_error,
        resolve_address,
    )

_STOP = False
_SERVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
READ_SIZE = 64 * 1024


def _stop(signum: int, frame: Any) -> None:
    global _STOP
    _STOP = True


def _pause(seconds: float) -> None:
    deadline = time.monotonic() + seconds
    while not _STOP:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(0.1, remaining))


class ChaosRunner:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.random = random.Random(args.seed)
        self.pidfds: dict[int, int] = {}
        self.address = resolve_address(args.host, args.port)
        self.compose = [
            "docker",
            "compose",
            "--file",
            str(args.compose_file.resolve()),
        ]

        if args.project_name:
            self.compose.extend((
                "--project-name", args.project_name
            ))

        if args.node_pid:
            if (
                not hasattr(os, "pidfd_open")
                or not hasattr(signal, "pidfd_send_signal")
            ):
                raise ValueError(
                    "safe local PID injection requires Linux "
                    "pidfd support; use Compose mode otherwise"
                )
            try:
                for pid in set(args.node_pid):
                    fd = os.pidfd_open(pid, 0)
                    os.set_inheritable(fd, False)
                    self.pidfds[pid] = fd
            except BaseException:
                self.close()
                raise

    def close(self) -> None:
        for fd in self.pidfds.values():
            os.close(fd)
        self.pidfds.clear()

    def command(self, arguments: list[str]) -> str:
        result = subprocess.run(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=self.args.command_timeout,
            check=False,
        )
        if result.returncode:
            raise RuntimeError(
                f"command failed with status {result.returncode}: "
                f"{result.stderr.strip()[:512]}"
            )
        return result.stdout.strip()

    def _state(self, container_id: str) -> dict[str, Any]:
        output = self.command([
            "docker",
            "inspect",
            "--format",
            "{{json .State}}",
            container_id,
        ])
        return json.loads(output)

    def node_signal(self) -> dict[str, Any]:
        chosen = self.random.choice((
            signal.SIGINT, signal.SIGTERM
        ))

        if self.args.node_pid:
            pid = self.random.choice(self.args.node_pid)
            try:
                signal.pidfd_send_signal(
                    self.pidfds[pid], chosen, None, 0
                )
            except ProcessLookupError:
                return {
                    "target_pid": pid,
                    "skipped": "original node has exited",
                }
            return {
                "target_pid": pid,
                "signal": chosen.name,
                "restarted": False,
            }

        service = self.random.choice(self.args.node_service)
        ids = self.command(
            self.compose + ["ps", "--all", "--quiet", service]
        ).splitlines()
        if len(ids) != 1:
            raise RuntimeError(
                f"expected one container for service {service!r}"
            )

        container_id = ids[0]
        original = self._state(container_id)
        if not original["Running"]:
            self.command(self.compose + ["start", service])
            return {
                "service": service,
                "skipped": "node was stopped",
                "restarted": True,
            }

        self.command([
            "docker",
            "kill",
            "--signal",
            chosen.name,
            container_id,
        ])

        deadline = time.monotonic() + self.args.recovery_timeout
        stopped = False
        automatically_restarted = False

        while time.monotonic() < deadline:
            current = self._state(container_id)
            if not current["Running"]:
                stopped = True
                break
            if current["StartedAt"] != original["StartedAt"]:
                automatically_restarted = True
                break
            time.sleep(0.1)

        # Finish bounded victim recovery even if the runner is stopping.
        self.command(self.compose + ["start", service])
        if not (stopped or automatically_restarted):
            raise RuntimeError(
                f"{service} did not exit after {chosen.name}"
            )

        return {
            "service": service,
            "signal": chosen.name,
            "restarted": True,
            "automatic_restart": automatically_restarted,
        }

    def redis_connections(self) -> dict[str, Any]:
        killed: dict[str, int] = {}

        for kind in ("pubsub", "normal"):
            output = self.command(
                self.compose
                + [
                    "exec",
                    "-T",
                    self.args.redis_service,
                    "redis-cli",
                    "--raw",
                    "CLIENT",
                    "KILL",
                    "TYPE",
                    kind,
                    "SKIPME",
                    "yes",
                ]
            )
            killed[kind] = int(output)

        return {
            "redis_service": self.args.redis_service,
            "connections_killed": killed,
        }

    def corrupt_stream(self) -> dict[str, Any]:
        vector = self.random.choice((
            "magic",
            "version",
            "flags",
            "length",
            "torn",
            "random",
        ))
        request_id = self.random.randrange(1, 0x100000000)
        header = bytearray(struct.pack(
            "!HBBBBII",
            0xCE57,
            1,
            5,
            0,
            0,
            request_id,
            8,
        ))
        expected: int | None = None

        if vector == "magic":
            header[0:2] = b"\x00\x00"
            packet = bytes(header) + b"\x00" * 8
            expected = 1
        elif vector == "version":
            header[2] = 2
            packet = bytes(header) + b"\x00" * 8
            expected = 2
        elif vector == "flags":
            header[4] = 1
            packet = bytes(header) + b"\x00" * 8
            expected = 4
        elif vector == "length":
            struct.pack_into("!I", header, 10, 0xFFFFFFFF)
            packet = bytes(header)
            expected = 3
        elif vector == "torn":
            packet = bytes(
                header[:self.random.randrange(1, 14)]
            )
        else:
            packet = (
                b"\x00\x00"
                + self.random.randbytes(
                    self.random.randrange(14, 128)
                )
            )
            expected = 1

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setblocking(False)
        deadline = time.monotonic() + self.args.network_timeout
        offset = 0
        connecting = True
        write_shutdown = False
        closed = False
        errors: list[int] = []
        decoder = FrameStream()

        try:
            error = sock.connect_ex(self.address)
            if error not in (
                0,
                errno.EINPROGRESS,
                errno.EWOULDBLOCK,
                errno.EALREADY,
                errno.EINTR,
            ):
                raise OSError(error, os.strerror(error))
            connecting = error != 0

            with selectors.DefaultSelector() as selector:
                selector.register(
                    sock,
                    selectors.EVENT_READ | selectors.EVENT_WRITE,
                )

                while time.monotonic() < deadline and not closed:
                    remaining = deadline - time.monotonic()

                    for key, mask in selector.select(
                        max(0.0, remaining)
                    ):
                        if mask & selectors.EVENT_WRITE:
                            if connecting:
                                error = sock.getsockopt(
                                    socket.SOL_SOCKET,
                                    socket.SO_ERROR,
                                )
                                if error:
                                    raise OSError(
                                        error, os.strerror(error)
                                    )
                                connecting = False

                            if offset < len(packet):
                                try:
                                    count = sock.send(
                                        memoryview(packet)[offset:]
                                    )
                                except (
                                    BlockingIOError,
                                    InterruptedError,
                                ):
                                    count = None

                                if count is not None:
                                    if count <= 0:
                                        raise WireError(
                                            "corruption send "
                                            "made no progress"
                                        )
                                    offset += count

                            if offset == len(packet):
                                if vector == "torn" and not write_shutdown:
                                    sock.shutdown(socket.SHUT_WR)
                                    write_shutdown = True
                                selector.modify(
                                    sock, selectors.EVENT_READ
                                )

                        if mask & selectors.EVENT_READ:
                            try:
                                data = sock.recv(READ_SIZE)
                            except (
                                BlockingIOError,
                                InterruptedError,
                            ):
                                continue
                            except ConnectionResetError:
                                closed = True
                                break

                            if not data:
                                closed = True
                                break

                            for frame in decoder.feed(data):
                                if frame.kind != 8:
                                    raise WireError(
                                        "unexpected reply "
                                        "to malformed stream"
                                    )
                                code, fatal, message = decode_error(frame)
                                if not fatal:
                                    raise WireError(
                                        "framing failure was not fatal"
                                    )
                                errors.append(code)

            if offset != len(packet):
                raise WireError(
                    "malformed test packet was not fully transmitted"
                )
            if not closed:
                raise WireError(
                    "node did not close malformed input before timeout"
                )
            if (
                errors
                and expected is not None
                and any(code != expected for code in errors)
            ):
                raise WireError(
                    f"unexpected framing error codes: {errors}"
                )

            return {
                "vector": vector,
                "bytes_sent": offset,
                "closed": closed,
                "error_codes": errors,
            }
        finally:
            sock.close()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bounded, explicitly targeted Victory chaos runner"
    )
    parser.add_argument(
        "--compose-file",
        type=Path,
        default=(
            Path(__file__).resolve().parents[1]
            / "deploy/docker-compose.yml"
        ),
    )
    parser.add_argument(
        "--project-name",
        help="Compose project override, matching the deployed stack",
    )
    parser.add_argument("--node-service", action="append")
    parser.add_argument(
        "--node-pid",
        action="append",
        type=int,
        help=(
            "explicit local node PID; local victims "
            "are not respawned"
        ),
    )
    parser.add_argument("--redis-service", default="redis")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--faults", default="signal,redis,bytes")
    parser.add_argument("--seed", type=int)
    parser.add_argument(
        "--duration",
        type=float,
        default=60.0,
        help="seconds; zero runs until interrupted",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="fault limit; zero uses the duration limit",
    )
    parser.add_argument(
        "--min-interval", type=float, default=1.0
    )
    parser.add_argument(
        "--max-interval", type=float, default=3.0
    )
    parser.add_argument(
        "--command-timeout", type=float, default=15.0
    )
    parser.add_argument(
        "--recovery-timeout", type=float, default=10.0
    )
    parser.add_argument(
        "--network-timeout", type=float, default=3.0
    )
    args = parser.parse_args()
    runner: ChaosRunner | None = None

    try:
        faults = [
            value.strip()
            for value in args.faults.split(",")
            if value.strip()
        ]
        if not faults or any(
            value not in ("signal", "redis", "bytes")
            for value in faults
        ):
            raise ValueError(
                "faults must be selected from signal,redis,bytes"
            )

        args.node_service = (
            args.node_service or ["victory1", "victory2"]
        )
        if any(
            not _SERVICE.fullmatch(value)
            for value in args.node_service + [args.redis_service]
        ):
            raise ValueError("invalid Compose service name")

        if args.node_pid and any(
            pid <= 1 or pid == os.getpid()
            for pid in args.node_pid
        ):
            raise ValueError(
                "local node PIDs must be greater than one "
                "and different from this process"
            )

        if not 1 <= args.port <= 65535 or args.count < 0:
            raise ValueError("invalid port or fault count")

        if not math.isfinite(args.duration) or args.duration < 0:
            raise ValueError(
                "duration must be finite and nonnegative"
            )

        for value in (
            args.min_interval,
            args.max_interval,
            args.command_timeout,
            args.recovery_timeout,
            args.network_timeout,
        ):
            if not math.isfinite(value) or not 0 < value <= 3600:
                raise ValueError(
                    "intervals and timeouts must be "
                    "within (0, 3600] seconds"
                )

        if args.min_interval > args.max_interval:
            raise ValueError("min-interval exceeds max-interval")

        requires_compose = (
            "redis" in faults
            or ("signal" in faults and not args.node_pid)
        )
        if requires_compose and not args.compose_file.is_file():
            raise ValueError("Compose file does not exist")

        if args.node_pid and os.name != "posix":
            raise ValueError(
                "local PID signal injection requires POSIX"
            )

        signal.signal(signal.SIGINT, _stop)
        signal.signal(signal.SIGTERM, _stop)

        if args.seed is None:
            args.seed = int.from_bytes(os.urandom(8), "big")

        runner = ChaosRunner(args)
        print(
            json.dumps({
                "event": "start",
                "seed": args.seed,
                "faults": faults,
            }),
            flush=True,
        )

        deadline = (
            time.monotonic() + args.duration
            if args.duration else None
        )
        attempts = failures = 0

        while (
            not _STOP
            and (
                deadline is None
                or time.monotonic() < deadline
            )
        ):
            if args.count and attempts >= args.count:
                break

            fault = runner.random.choice(faults)
            attempts += 1
            started = time.monotonic()

            try:
                if fault == "signal":
                    details = runner.node_signal()
                elif fault == "redis":
                    details = runner.redis_connections()
                else:
                    details = runner.corrupt_stream()

                event = {"ok": True, "details": details}
            except Exception as exc:
                failures += 1
                event = {
                    "ok": False,
                    "error": f"{type(exc).__name__}: {exc}",
                }

            print(
                json.dumps({
                    "attempt": attempts,
                    "fault": fault,
                    "elapsed_seconds": time.monotonic() - started,
                    **event,
                }),
                flush=True,
            )

            delay = runner.random.uniform(
                args.min_interval, args.max_interval
            )
            if deadline is not None:
                delay = min(
                    delay,
                    max(0.0, deadline - time.monotonic()),
                )
            _pause(delay)

        print(
            json.dumps({
                "attempts": attempts,
                "failed_injections": failures,
                "stopped": _STOP,
                "seed": args.seed,
            }),
            flush=True,
        )
        return 1 if failures else 0

    except Exception as exc:
        print(
            json.dumps({
                "error": f"{type(exc).__name__}: {exc}"
            }),
            file=sys.stderr,
        )
        return 1
    finally:
        if runner is not None:
            runner.close()


if __name__ == "__main__":
    raise SystemExit(main())