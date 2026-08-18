"""Small, operation-scoped relay client for Nostr publish and query."""

from __future__ import annotations

import asyncio
import json
import secrets
from dataclasses import dataclass
from typing import Any, Iterable

import aiohttp

from .errors import RelayError, RelayRejectedError
from .events import Event


@dataclass(frozen=True)
class PublishResult:
    relay: str
    event_id: str
    accepted: bool
    message: str = ""


class RelayClient:
    def __init__(self, url: str, *, timeout: float = 10.0) -> None:
        if not url.startswith(("ws://", "wss://")):
            raise ValueError("Relay URL must use ws:// or wss://")
        self.url = url
        self.timeout = timeout

    async def publish(self, event: Event) -> PublishResult:
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.ws_connect(self.url) as websocket:
                await websocket.send_json(["EVENT", event.data()])
                while True:
                    message = await websocket.receive()
                    if message.type is aiohttp.WSMsgType.TEXT:
                        data = json.loads(message.data)
                        if len(data) >= 3 and data[0] == "OK" and data[1] == event.id:
                            result = PublishResult(
                                relay=self.url,
                                event_id=event.id,
                                accepted=bool(data[2]),
                                message=str(data[3]) if len(data) > 3 else "",
                            )
                            if not result.accepted:
                                raise RelayRejectedError(
                                    f"Relay {self.url} rejected {event.id}: {result.message}"
                                )
                            return result
                    elif message.type in {aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR}:
                        raise RelayError(f"Relay {self.url} closed before acknowledging the event")

    async def query(self, filters: dict[str, Any] | Iterable[dict[str, Any]]) -> list[Event]:
        request_filters = [filters] if isinstance(filters, dict) else list(filters)
        subscription_id = secrets.token_hex(8)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        events: dict[str, Event] = {}
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.ws_connect(self.url) as websocket:
                await websocket.send_json(["REQ", subscription_id, *request_filters])
                while True:
                    message = await websocket.receive()
                    if message.type is aiohttp.WSMsgType.TEXT:
                        data = json.loads(message.data)
                        if len(data) >= 3 and data[0] == "EVENT" and data[1] == subscription_id:
                            event = Event.load(data[2], validate=True)
                            if event is not None:
                                events[event.id] = event
                        elif len(data) >= 2 and data[0] == "EOSE" and data[1] == subscription_id:
                            await websocket.send_json(["CLOSE", subscription_id])
                            return sorted(events.values(), key=lambda event: (event.created_at, event.id))
                    elif message.type in {aiohttp.WSMsgType.CLOSED, aiohttp.WSMsgType.ERROR}:
                        raise RelayError(f"Relay {self.url} closed before EOSE")


class RelayPool:
    def __init__(self, relays: Iterable[str], *, timeout: float = 10.0) -> None:
        self.relays = tuple(dict.fromkeys(relays))
        if not self.relays:
            raise ValueError("At least one relay is required")
        self.timeout = timeout

    async def publish(self, event: Event, *, require: int = 1) -> list[PublishResult]:
        if not 1 <= require <= len(self.relays):
            raise ValueError("Invalid relay acknowledgement requirement")
        outcomes = await asyncio.gather(
            *(RelayClient(relay, timeout=self.timeout).publish(event) for relay in self.relays),
            return_exceptions=True,
        )
        accepted = [outcome for outcome in outcomes if isinstance(outcome, PublishResult) and outcome.accepted]
        if len(accepted) < require:
            failures = "; ".join(str(outcome) for outcome in outcomes if isinstance(outcome, Exception))
            raise RelayError(
                f"Event was acknowledged by {len(accepted)}/{len(self.relays)} relays; {failures}"
            )
        return accepted

    async def query(self, filters: dict[str, Any] | Iterable[dict[str, Any]]) -> list[Event]:
        outcomes = await asyncio.gather(
            *(RelayClient(relay, timeout=self.timeout).query(filters) for relay in self.relays),
            return_exceptions=True,
        )
        merged: dict[str, Event] = {}
        for outcome in outcomes:
            if isinstance(outcome, list):
                for event in outcome:
                    merged[event.id] = event
        if not merged and all(isinstance(outcome, Exception) for outcome in outcomes):
            raise RelayError("All relay queries failed: " + "; ".join(str(outcome) for outcome in outcomes))
        return sorted(merged.values(), key=lambda event: (event.created_at, event.id))
