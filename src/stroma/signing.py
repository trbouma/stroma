"""Signer abstraction used by NIP-59 and Acorn."""

from __future__ import annotations

from abc import ABC, abstractmethod

from .events import Event
from .keys import Keys
from .nip44 import NIP44Encrypt


class Signer(ABC):
    @abstractmethod
    async def get_public_key(self) -> str: ...

    @abstractmethod
    async def sign_event(self, event: Event) -> None: ...

    @abstractmethod
    async def nip44_encrypt(self, plaintext: str, public_key: str) -> str: ...

    @abstractmethod
    async def nip44_decrypt(self, payload: str, public_key: str) -> str: ...

    async def ready_post(self, event: Event) -> Event:
        event.pub_key = await self.get_public_key()
        await self.sign_event(event)
        return event


class BasicKeySigner(Signer):
    def __init__(self, keys: Keys) -> None:
        if keys.private_key_hex() is None:
            raise ValueError("BasicKeySigner requires a private key")
        self.keys = keys
        self.nip44 = NIP44Encrypt(keys)

    async def get_public_key(self) -> str:
        return self.keys.public_key_hex()

    async def sign_event(self, event: Event) -> None:
        event.sign(self.keys)

    async def nip44_encrypt(
        self,
        plaintext: str | None = None,
        public_key: str | None = None,
        *,
        plain_text: str | None = None,
        to_pub_k: str | None = None,
    ) -> str:
        message = plaintext if plaintext is not None else plain_text
        recipient = public_key if public_key is not None else to_pub_k
        if message is None or recipient is None:
            raise ValueError("NIP-44 plaintext and recipient are required")
        return self.nip44.encrypt(message, recipient)

    async def nip44_decrypt(
        self,
        payload: str,
        public_key: str | None = None,
        *,
        for_pub_k: str | None = None,
    ) -> str:
        peer = public_key if public_key is not None else for_pub_k
        if peer is None:
            raise ValueError("NIP-44 peer public key is required")
        return self.nip44.decrypt(payload, peer)
