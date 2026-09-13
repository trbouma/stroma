"""Narrow compatibility surface used while Acorn migrates from Monstr.

This module intentionally implements only the behavior exercised by Acorn. Its
normal query and publish operations remain operation-scoped and bounded.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any, Callable, Iterable

from .events import Event
from .relay import RelayClient, RelayPool


class util_funcs:
    @staticmethod
    def str_tails(value: str, taillen: int = 4) -> str:
        return value if len(value) <= taillen * 2 else f"{value[:taillen]}...{value[-taillen:]}"

    @staticmethod
    def date_as_ticks(value: datetime) -> int:
        return int(value.timestamp())


class DeduplicateAcceptor:
    """Small event-ID acceptor retained for downstream compatibility."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def accept_event(self, event: Event) -> bool:
        if event.id in self._seen:
            return False
        self._seen.add(event.id)
        return True


class Client:
    """One-relay compatibility client with bounded operation methods."""

    def __init__(self, url: str, *, timeout: float = 10.0, **_: Any) -> None:
        self.url = url
        self.timeout = float(timeout)
        self._ended = asyncio.Event()

    async def query(self, filters, **_: Any) -> list[Event]:
        return await RelayClient(self.url, timeout=self.timeout).query(filters)

    def publish(self, event: Event):
        return asyncio.create_task(
            RelayClient(self.url, timeout=self.timeout).publish(event)
        )

    async def run(self) -> None:
        await self._ended.wait()

    async def wait_connect(self, timeout: float | None = None, **_: Any) -> None:
        await RelayClient(self.url, timeout=timeout or self.timeout).probe()

    def subscribe(self, *_, **__) -> str:
        raise NotImplementedError(
            "Long-lived subscriptions are not part of Stroma's Acorn boundary"
        )

    def unsubscribe(self, *_, **__) -> None:
        return None

    def end(self) -> None:
        self._ended.set()


class ClientPool:
    """Acorn-shaped adapter backed by operation-scoped Stroma relay calls."""

    def __init__(
        self,
        clients: str | Client | Iterable[str | Client],
        *,
        timeout: float | None = None,
        min_connect: int = 1,
        error_min_con_fail: bool = False,
        on_connect: Callable | None = None,
        on_status: Callable | None = None,
        on_eose: Callable | None = None,
        on_notice: Callable | None = None,
        on_auth: Callable | None = None,
        **_: Any,
    ) -> None:
        if isinstance(clients, (str, Client)):
            clients = [clients]
        self.clients = [
            item if isinstance(item, Client) else Client(item, timeout=timeout or 10.0)
            for item in clients
        ]
        if not self.clients:
            raise ValueError("At least one relay is required")
        self.relays = tuple(client.url for client in self.clients)
        self.timeout = float(timeout or 10.0)
        self.min_connect = int(min_connect)
        self.error_min_con_fail = bool(error_min_con_fail)
        self.on_connect = on_connect
        self.on_status = on_status
        self.on_eose = on_eose
        self.on_notice = on_notice
        self.on_auth = on_auth
        self._ended = asyncio.Event()
        self._publish_tasks: set[asyncio.Task] = set()

    async def __aenter__(self) -> "ClientPool":
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> bool:
        if self._publish_tasks:
            await asyncio.gather(*tuple(self._publish_tasks), return_exceptions=False)
        self.end()
        return False

    async def query(self, filters=None, *, timeout: float | None = None, **_: Any) -> list[Event]:
        return await RelayPool(
            self.relays,
            timeout=timeout or self.timeout,
        ).query(filters or {})

    def publish(self, event: Event):
        task = asyncio.create_task(
            RelayPool(self.relays, timeout=self.timeout).publish(event)
        )
        self._publish_tasks.add(task)
        return task

    async def wait_connect(
        self,
        timeout: float | None = None,
        min_connect: int | None = None,
        error_min_con_fail: bool | None = None,
    ) -> None:
        required = self.min_connect if min_connect is None else int(min_connect)
        outcomes = await asyncio.gather(
            *(RelayClient(relay, timeout=timeout or self.timeout).probe() for relay in self.relays),
            return_exceptions=True,
        )
        connected = sum(outcome is True for outcome in outcomes)
        strict = self.error_min_con_fail if error_min_con_fail is None else error_min_con_fail
        if connected < required and (strict or connected == 0):
            raise ConnectionError(
                f"Connected to {connected}/{len(self.relays)} relays; required {required}"
            )

    async def run(self) -> None:
        await self.wait_connect()
        if self.on_connect is not None:
            for client in self.clients:
                result = self.on_connect(client)
                if asyncio.iscoroutine(result):
                    await result
        await self._ended.wait()

    def subscribe(self, *_, **__) -> str:
        raise NotImplementedError(
            "Long-lived subscriptions are not part of Stroma's Acorn boundary"
        )

    def unsubscribe(self, *_, **__) -> None:
        return None

    def end(self) -> None:
        self._ended.set()
        for client in self.clients:
            client.end()
        for task in tuple(self._publish_tasks):
            if not task.done():
                task.cancel()
