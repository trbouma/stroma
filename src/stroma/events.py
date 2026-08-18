"""NIP-01 event serialization, signing, and validation."""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from copy import deepcopy
from typing import Any, Iterable, Iterator

from coincurve import PublicKeyXOnly

from .errors import EventError
from .keys import Keys


class EventTags:
    def __init__(self, tags: Iterable[Iterable[Any]] | str | None = None) -> None:
        if isinstance(tags, str):
            try:
                tags = json.loads(tags)
            except json.JSONDecodeError as exc:
                raise EventError("Event tags are not valid JSON") from exc
        self._tags = [list(tag) for tag in (tags or [])]

    def get_tags(self, name: str) -> list[list[Any]]:
        return [tag[1:] for tag in self._tags if tag and tag[0] == name]

    def get_tags_value(self, name: str) -> list[Any]:
        return [tag[0] for tag in self.get_tags(name) if tag]

    def get_tag_value_pos(self, name: str, pos: int = 0, default: Any = None) -> Any:
        values = self.get_tags_value(name)
        try:
            return values[pos]
        except IndexError:
            return default

    @property
    def p_tags(self) -> list[str]:
        return [value for value in self.get_tags_value("p") if isinstance(value, str) and len(value) == 64]

    @property
    def e_tags(self) -> list[str]:
        return [value for value in self.get_tags_value("e") if isinstance(value, str) and len(value) == 64]

    @property
    def tag_names(self) -> set[str]:
        return {str(tag[0]) for tag in self._tags if tag}

    def append(self, tag: Iterable[Any]) -> None:
        self._tags.append(list(tag))

    def as_list(self) -> list[list[Any]]:
        return deepcopy(self._tags)

    def __iter__(self) -> Iterator[list[Any]]:
        return iter(self._tags)

    def __len__(self) -> int:
        return len(self._tags)

    def __getitem__(self, item: int) -> list[Any]:
        return self._tags[item]

    def __str__(self) -> str:
        return json.dumps(self._tags, separators=(",", ":"), ensure_ascii=False)


class Event:
    KIND_META = 0
    KIND_TEXT_NOTE = 1
    KIND_ENCRYPT = 4
    KIND_DELETE = 5
    KIND_SEAL = 13
    KIND_RUMOUR = 14
    KIND_GIFT_WRAP = 1059

    def __init__(
        self,
        *,
        id: str | None = None,
        sig: str | None = None,
        kind: int = KIND_TEXT_NOTE,
        content: str = "",
        tags: Iterable[Iterable[Any]] | EventTags | None = None,
        pub_key: str | None = None,
        created_at: int | None = None,
    ) -> None:
        self._id = id
        self._sig = sig
        self.kind = int(kind)
        self.content = content
        self.tags = tags if isinstance(tags, EventTags) else EventTags(tags)
        self.pub_key = pub_key
        self.created_at = int(time.time()) if created_at is None else int(created_at)

    @staticmethod
    def load(event_data: str | dict[str, Any], validate: bool = False) -> "Event | None":
        if isinstance(event_data, str):
            try:
                event_data = json.loads(event_data)
            except json.JSONDecodeError as exc:
                raise EventError("Event is not valid JSON") from exc
        if not isinstance(event_data, dict):
            raise EventError("Event must be a mapping")
        event = Event(
            id=event_data.get("id"),
            sig=event_data.get("sig"),
            kind=event_data.get("kind", Event.KIND_TEXT_NOTE),
            content=event_data.get("content", ""),
            tags=event_data.get("tags", []),
            pub_key=event_data.get("pubkey"),
            created_at=event_data.get("created_at"),
        )
        return event if not validate or event.is_valid() else None

    @property
    def id(self) -> str:
        calculated = self.calculate_id()
        if self._id is None:
            self._id = calculated
        return self._id

    @id.setter
    def id(self, value: str | None) -> None:
        self._id = value

    @property
    def sig(self) -> str | None:
        return self._sig

    @sig.setter
    def sig(self, value: str | None) -> None:
        self._sig = value

    def serialize(self) -> str:
        if self.pub_key is None:
            raise EventError("Event public key is required")
        body = [0, self.pub_key, self.created_at, self.kind, self.tags.as_list(), self.content]
        return json.dumps(body, separators=(",", ":"), ensure_ascii=False)

    def calculate_id(self) -> str:
        return hashlib.sha256(self.serialize().encode("utf-8")).hexdigest()

    def sign(self, private_key: str | Keys) -> str:
        keys = private_key if isinstance(private_key, Keys) else Keys(priv_k=private_key)
        if keys.private_key is None:
            raise EventError("A private key is required to sign an event")
        self.pub_key = keys.public_key_hex()
        self._id = self.calculate_id()
        self._sig = keys.private_key.sign_schnorr(
            bytes.fromhex(self._id),
            aux_randomness=secrets.token_bytes(32),
        ).hex()
        return self._sig

    def is_valid(self) -> bool:
        if self.pub_key is None or self._id is None or self._sig is None:
            return False
        if self.calculate_id() != self._id:
            return False
        try:
            return PublicKeyXOnly(bytes.fromhex(self.pub_key)).verify(
                bytes.fromhex(self._sig), bytes.fromhex(self._id)
            )
        except Exception:
            return False

    def data(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "pubkey": self.pub_key,
            "created_at": self.created_at,
            "kind": self.kind,
            "tags": self.tags.as_list(),
            "content": self.content,
            "sig": self._sig,
        }

    def copy(self) -> "Event":
        return Event.load(self.data())  # type: ignore[return-value]

    @staticmethod
    def is_event_id(value: str) -> bool:
        try:
            return len(value) == 64 and len(bytes.fromhex(value)) == 32
        except (TypeError, ValueError):
            return False

    @staticmethod
    def merge(*event_sets: Iterable["Event"]) -> list["Event"]:
        found: set[str] = set()
        merged: list[Event] = []
        for events in event_sets:
            for event in events:
                if event.id not in found:
                    found.add(event.id)
                    merged.append(event)
        return merged
