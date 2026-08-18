"""NIP-19 bech32 and TLV entities used by Acorn."""

from __future__ import annotations

from typing import Any

from bech32 import bech32_decode, bech32_encode, convertbits

from .errors import KeyError
from .keys import Keys


class UnknownEntity(KeyError):
    pass


def _tlv_field(tag: int, value: bytes) -> bytes:
    if not 0 <= tag <= 255 or len(value) > 255:
        raise UnknownEntity("NIP-19 TLV field is too large")
    return bytes((tag, len(value))) + value


def _tlv_decode(raw: bytes) -> list[tuple[int, bytes]]:
    fields: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(raw):
        if offset + 2 > len(raw):
            raise UnknownEntity("Truncated NIP-19 TLV field")
        tag, length = raw[offset], raw[offset + 1]
        offset += 2
        if offset + length > len(raw):
            raise UnknownEntity("Truncated NIP-19 TLV value")
        fields.append((tag, raw[offset : offset + length]))
        offset += length
    return fields


class Entities:
    @staticmethod
    def encode(name: str, data: str | dict[str, Any]) -> str:
        if name in {"npub", "nsec", "note"}:
            if not isinstance(data, str):
                raise UnknownEntity(f"{name} requires a hex string")
            return Keys.hex_to_bech32(data, prefix=name)
        if not isinstance(data, dict):
            raise UnknownEntity(f"{name} requires a mapping")

        raw = b""
        if name == "nprofile":
            raw += _tlv_field(0, bytes.fromhex(data["pubkey"]))
        elif name == "nevent":
            raw += _tlv_field(0, bytes.fromhex(data["event_id"]))
        elif name == "nrelay":
            raw += _tlv_field(0, data["relay"].encode())
        elif name == "naddr":
            raw += _tlv_field(0, data["id"].encode())
        else:
            raise UnknownEntity(name)

        relays = data.get("relay", [])
        if isinstance(relays, str):
            relays = [relays]
        if name in {"nprofile", "nevent", "naddr"}:
            for relay in relays:
                raw += _tlv_field(1, relay.encode())
        if name in {"nevent", "naddr"} and data.get("author") is not None:
            raw += _tlv_field(2, bytes.fromhex(data["author"]))
        if name in {"nevent", "naddr"} and data.get("kind") is not None:
            raw += _tlv_field(3, int(data["kind"]).to_bytes(4, "big"))

        converted = convertbits(raw, 8, 5, True)
        if converted is None:
            raise UnknownEntity("Unable to encode NIP-19 entity")
        return bech32_encode(name, converted)

    @staticmethod
    def decode(value: str) -> str | dict[str, Any]:
        prefix, values = bech32_decode(value)
        if prefix is None or values is None:
            raise UnknownEntity("Invalid NIP-19 entity")
        converted = convertbits(values, 5, 8, False)
        if converted is None:
            raise UnknownEntity("Invalid NIP-19 payload")
        raw = bytes(converted)
        if prefix in {"npub", "nsec", "note"}:
            if len(raw) != 32:
                raise UnknownEntity(f"Invalid {prefix} length")
            return raw.hex()

        fields = _tlv_decode(raw)
        result: dict[str, Any] = {}
        relays: list[str] = []
        for tag, field in fields:
            if tag == 0:
                key = "pubkey" if prefix == "nprofile" else "event_id" if prefix == "nevent" else "relay" if prefix == "nrelay" else "id"
                result[key] = field.hex() if prefix in {"nprofile", "nevent"} else field.decode()
            elif tag == 1:
                relays.append(field.decode())
            elif tag == 2:
                result["author"] = field.hex()
            elif tag == 3:
                result["kind"] = int.from_bytes(field, "big")
        if relays:
            result["relay"] = relays[0] if len(relays) == 1 else relays
        if prefix not in {"nprofile", "nevent", "nrelay", "naddr"}:
            raise UnknownEntity(prefix)
        return result
