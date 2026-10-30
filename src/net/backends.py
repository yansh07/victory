"""Level-triggered readiness backends without application policy."""

from __future__ import annotations

import errno
import math
import select
import selectors
import sys
import time
from dataclasses import dataclass
from typing import TypeAlias, cast

READ = 1
WRITE = 2
ERROR = 4
HANGUP = 8
PEER_CLOSED = 16


@dataclass(frozen=True, slots=True)
class Event:
    fd: int
    mask: int
    data: object


@dataclass(frozen=True, slots=True)
class _Registration:
    fd: int
    mask: int
    data: object


def _validate_interest(fd: int, mask: int) -> None:
    if isinstance(fd, bool) or not isinstance(fd, int) or fd < 0:
        raise ValueError("fd must be a nonnegative integer")

    if (
        isinstance(mask, bool)
        or not isinstance(mask, int)
        or mask == 0
        or mask & ~(READ | WRITE)
    ):
        raise ValueError("interest must contain READ, WRITE, or both")


def _deadline(timeout: float | None) -> float | None:
    if timeout is None:
        return None
    if not math.isfinite(timeout) or timeout < 0:
        raise ValueError(
            "timeout must be finite and nonnegative, or None"
        )
    return time.monotonic() + timeout


def _remaining(deadline: float | None) -> float | None:
    if deadline is None:
        return None
    return max(0.0, deadline - time.monotonic())


class EpollBackend:
    """Native Linux epoll with level-triggered readiness."""

    def __init__(self, max_events: int = 1024) -> None:
        if (
            not sys.platform.startswith("linux")
            or not hasattr(select, "epoll")
        ):
            raise RuntimeError("native epoll requires Linux")

        if (
            isinstance(max_events, bool)
            or not isinstance(max_events, int)
            or max_events < 1
        ):
            raise ValueError("max_events must be a positive integer")

        self._poller = select.epoll()
        self._max_events = max_events
        self._registrations: dict[int, _Registration] = {}
        self._closed = False

    def _check_open(self) -> None:
        if self._closed:
            raise RuntimeError("backend is closed")

    @staticmethod
    def _native_mask(mask: int) -> int:
        events = 0

        if mask & READ:
            events |= select.EPOLLIN
            events |= getattr(select, "EPOLLRDHUP", 0)

        if mask & WRITE:
            events |= select.EPOLLOUT

        return events

    def register(
        self,
        fd: int,
        mask: int,
        data: object = None,
    ) -> None:
        self._check_open()
        _validate_interest(fd, mask)

        if fd in self._registrations:
            raise KeyError(f"fd {fd} is already registered")

        while True:
            try:
                self._poller.register(fd, self._native_mask(mask))
                break
            except OSError as error:
                if error.errno != errno.EINTR:
                    raise

        self._registrations[fd] = _Registration(fd, mask, data)

    def modify(
        self,
        fd: int,
        mask: int,
        data: object = None,
    ) -> None:
        self._check_open()
        _validate_interest(fd, mask)

        if fd not in self._registrations:
            raise KeyError(f"fd {fd} is not registered")

        while True:
            try:
                self._poller.modify(fd, self._native_mask(mask))
                break
            except OSError as error:
                if error.errno != errno.EINTR:
                    raise

        self._registrations[fd] = _Registration(fd, mask, data)

    def unregister(self, fd: int) -> None:
        if self._closed or fd not in self._registrations:
            return

        while True:
            try:
                self._poller.unregister(fd)
                break
            except OSError as error:
                if error.errno == errno.EINTR:
                    continue
                if error.errno not in (errno.EBADF, errno.ENOENT):
                    raise
                break

        del self._registrations[fd]

    def poll(self, timeout: float | None = None) -> list[Event]:
        self._check_open()
        deadline = _deadline(timeout)

        while True:
            remaining = _remaining(deadline)
            try:
                ready = self._poller.poll(
                    -1.0 if remaining is None else remaining,
                    self._max_events,
                )
                break
            except OSError as error:
                if error.errno != errno.EINTR:
                    raise
                if (
                    deadline is not None
                    and time.monotonic() >= deadline
                ):
                    return []

        events: list[Event] = []

        # Capture registration identities before callbacks can reuse fds.
        for fd, native in ready:
            registration = self._registrations.get(fd)
            if registration is None:
                continue

            mask = 0

            if native & select.EPOLLIN:
                mask |= READ
            if native & select.EPOLLOUT:
                mask |= WRITE
            if native & select.EPOLLERR:
                mask |= ERROR
            if native & select.EPOLLHUP:
                mask |= HANGUP
            if native & getattr(select, "EPOLLRDHUP", 0):
                mask |= PEER_CLOSED

            if mask:
                events.append(Event(fd, mask, registration.data))

        return events

    def close(self) -> None:
        if self._closed:
            return

        self._closed = True
        self._registrations.clear()
        self._poller.close()


class SelectorBackend:
    """DefaultSelector fallback for macOS or explicit development mode."""

    def __init__(self) -> None:
        self._poller = selectors.DefaultSelector()
        self._closed = False

    def _check_open(self) -> None:
        if self._closed:
            raise RuntimeError("backend is closed")

    @staticmethod
    def _native_mask(mask: int) -> int:
        events = 0

        if mask & READ:
            events |= selectors.EVENT_READ
        if mask & WRITE:
            events |= selectors.EVENT_WRITE

        return events

    def register(
        self,
        fd: int,
        mask: int,
        data: object = None,
    ) -> None:
        self._check_open()
        _validate_interest(fd, mask)

        self._poller.register(
            fd,
            self._native_mask(mask),
            _Registration(fd, mask, data),
        )

    def modify(
        self,
        fd: int,
        mask: int,
        data: object = None,
    ) -> None:
        self._check_open()
        _validate_interest(fd, mask)

        self._poller.modify(
            fd,
            self._native_mask(mask),
            _Registration(fd, mask, data),
        )

    def unregister(self, fd: int) -> None:
        if self._closed:
            return

        try:
            self._poller.unregister(fd)
        except KeyError:
            return
        except OSError as error:
            if error.errno not in (errno.EBADF, errno.ENOENT):
                raise

    def poll(self, timeout: float | None = None) -> list[Event]:
        self._check_open()
        deadline = _deadline(timeout)

        while True:
            try:
                ready = self._poller.select(_remaining(deadline))
                break
            except OSError as error:
                if error.errno != errno.EINTR:
                    raise
                if (
                    deadline is not None
                    and time.monotonic() >= deadline
                ):
                    return []

        events: list[Event] = []

        for key, native in ready:
            registration = cast(_Registration, key.data)
            mask = 0

            if native & selectors.EVENT_READ:
                mask |= READ
            if native & selectors.EVENT_WRITE:
                mask |= WRITE

            events.append(
                Event(registration.fd, mask, registration.data)
            )

        return events

    def close(self) -> None:
        if self._closed:
            return

        self._closed = True
        self._poller.close()


Backend: TypeAlias = EpollBackend | SelectorBackend


def create_backend(
    *,
    development: bool = False,
    max_events: int = 1024,
) -> Backend:
    if sys.platform.startswith("linux") and not development:
        return EpollBackend(max_events=max_events)

    if sys.platform == "darwin" or development:
        return SelectorBackend()

    raise RuntimeError(
        "use Linux, macOS, or explicit development mode"
    )