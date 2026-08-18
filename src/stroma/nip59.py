"""NIP-59 gift wrapping with explicit, testable timestamp policy."""

from __future__ import annotations

import json
import secrets
import time

from .errors import GiftWrapError
from .events import Event
from .keys import Keys
from .signing import BasicKeySigner, Signer


class GiftWrap:
    def __init__(
        self,
        signer: Signer,
        *,
        jitter_seconds: int = 0,
        gift_wrap_kind: int = Event.KIND_GIFT_WRAP,
        preserve_rumour_kind: bool = True,
    ) -> None:
        if jitter_seconds < 0:
            raise ValueError("jitter_seconds must not be negative")
        self.signer = signer
        self.jitter_seconds = jitter_seconds
        self.gift_wrap_kind = gift_wrap_kind
        self.preserve_rumour_kind = preserve_rumour_kind

    def _created_at(self) -> int:
        now = int(time.time())
        return now - secrets.randbelow(self.jitter_seconds + 1) if self.jitter_seconds else now

    async def _make_rumour(self, event: Event) -> Event:
        return Event(
            kind=event.kind if self.preserve_rumour_kind else Event.KIND_RUMOUR,
            content=event.content,
            tags=event.tags.as_list(),
            pub_key=await self.signer.get_public_key(),
            created_at=event.created_at,
        )

    async def _make_seal(self, rumour: Event, recipient: str) -> Event:
        if rumour.sig is not None:
            raise GiftWrapError("A rumour must be unsigned")
        seal = Event(
            kind=Event.KIND_SEAL,
            content=await self.signer.nip44_encrypt(
                json.dumps(rumour.data(), separators=(",", ":")), recipient
            ),
            pub_key=await self.signer.get_public_key(),
            created_at=self._created_at(),
            tags=[],
        )
        await self.signer.sign_event(seal)
        return seal

    async def wrap(
        self,
        event: Event,
        recipient: str | Keys,
        *,
        expiration: int | None = None,
    ) -> tuple[Event, Keys]:
        recipient_hex = recipient.public_key_hex() if isinstance(recipient, Keys) else Keys(pub_k=recipient).public_key_hex()
        rumour = await self._make_rumour(event)
        seal = await self._make_seal(rumour, recipient_hex)
        ephemeral = Keys()
        ephemeral_signer = BasicKeySigner(ephemeral)
        tags: list[list[str]] = [["p", recipient_hex]]
        if expiration is not None:
            if int(expiration) <= 0:
                raise ValueError("expiration must be a positive Unix timestamp")
            tags.append(["expiration", str(int(expiration))])
        wrapper = Event(
            kind=self.gift_wrap_kind,
            content=await ephemeral_signer.nip44_encrypt(
                json.dumps(seal.data(), separators=(",", ":")), recipient_hex
            ),
            pub_key=ephemeral.public_key_hex(),
            created_at=self._created_at(),
            tags=tags,
        )
        await ephemeral_signer.sign_event(wrapper)
        return wrapper, ephemeral

    async def unwrap(self, wrapper: Event) -> Event:
        recipient = wrapper.tags.get_tag_value_pos("p")
        own_public_key = await self.signer.get_public_key()
        if recipient is None:
            raise GiftWrapError("Gift wrap has no recipient tag")
        if recipient != own_public_key:
            raise GiftWrapError("Gift wrap is addressed to another key")
        if not wrapper.is_valid():
            raise GiftWrapError("Gift wrap signature is invalid")
        seal_json = await self.signer.nip44_decrypt(wrapper.content, wrapper.pub_key or "")
        seal = Event.load(seal_json, validate=True)
        if seal is None:
            raise GiftWrapError("Seal signature is invalid")
        rumour_json = await self.signer.nip44_decrypt(seal.content, seal.pub_key or "")
        rumour = Event.load(rumour_json)
        assert rumour is not None
        if rumour.pub_key != seal.pub_key or rumour.sig is not None:
            raise GiftWrapError("Rumour and seal authors do not match")
        return rumour
