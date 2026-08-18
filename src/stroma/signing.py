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

    async def nip44_encrypt(self, plaintext: str, public_key: str) -> str:
        return self.nip44.encrypt(plaintext, public_key)

    async def nip44_decrypt(self, payload: str, public_key: str) -> str:
        return self.nip44.decrypt(payload, public_key)
