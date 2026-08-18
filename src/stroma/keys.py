"""secp256k1 key handling with the small compatibility surface Acorn uses."""

from __future__ import annotations

from bech32 import bech32_decode, bech32_encode, convertbits
from coincurve import PrivateKey, PublicKey

from .errors import KeyError


def _is_hex(value: str, length: int = 64) -> bool:
    if len(value) != length:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _bech32_encode(prefix: str, raw: bytes) -> str:
    converted = convertbits(raw, 8, 5, True)
    if converted is None:
        raise KeyError("Unable to encode key")
    return bech32_encode(prefix, converted)


def _bech32_decode(value: str, expected_prefix: str | None = None) -> tuple[str, bytes]:
    prefix, encoded = bech32_decode(value)
    if prefix is None or encoded is None:
        raise KeyError("Invalid bech32 value")
    if expected_prefix is not None and prefix != expected_prefix:
        raise KeyError(f"Expected {expected_prefix}, received {prefix}")
    converted = convertbits(encoded, 5, 8, False)
    if converted is None:
        raise KeyError("Invalid bech32 payload")
    return prefix, bytes(converted)


class Keys:
    """A Nostr keypair or public key.

    ``Keys()`` creates a new keypair. The positional form is retained for the
    small compatibility surface used by Acorn; explicit ``priv_k`` and
    ``pub_k`` arguments are preferred in new code.
    """

    def __init__(
        self,
        key: str | None = None,
        *,
        priv_k: str | None = None,
        pub_k: str | None = None,
    ) -> None:
        if sum(value is not None for value in (key, priv_k, pub_k)) > 1:
            raise KeyError("Provide only one of key, priv_k, or pub_k")

        self._private: PrivateKey | None = None
        self._public_hex: str

        if key is None and priv_k is None and pub_k is None:
            self._private = PrivateKey()
            self._public_hex = self._private.public_key.format(compressed=True)[1:].hex()
            return

        if priv_k is not None:
            raw = self._decode_private(priv_k)
            try:
                self._private = PrivateKey(raw)
            except Exception as exc:
                raise KeyError("Invalid private key") from exc
            self._public_hex = self._private.public_key.format(compressed=True)[1:].hex()
            return

        if pub_k is not None:
            self._public_hex = self._decode_public(pub_k)
            self._validate_public(self._public_hex)
            return

        assert key is not None
        if key.startswith("nsec"):
            raw = self._decode_private(key)
            self._private = PrivateKey(raw)
            self._public_hex = self._private.public_key.format(compressed=True)[1:].hex()
        else:
            self._public_hex = self._decode_public(key)
            self._validate_public(self._public_hex)

    @staticmethod
    def _decode_private(value: str) -> bytes:
        if value.startswith("nsec"):
            _, raw = _bech32_decode(value, "nsec")
        elif _is_hex(value):
            raw = bytes.fromhex(value)
        else:
            raise KeyError("Private key must be a 32-byte hex value or nsec")
        if len(raw) != 32:
            raise KeyError("Private key must be 32 bytes")
        return raw

    @staticmethod
    def _decode_public(value: str) -> str:
        if value.startswith("npub"):
            _, raw = _bech32_decode(value, "npub")
            value = raw.hex()
        if not _is_hex(value):
            raise KeyError("Public key must be a 32-byte hex value or npub")
        return value.lower()

    @staticmethod
    def _validate_public(public_hex: str) -> None:
        try:
            PublicKey(b"\x02" + bytes.fromhex(public_hex))
        except Exception as exc:
            raise KeyError("Invalid x-only public key") from exc

    @classmethod
    def get_key(cls, value: str) -> "Keys":
        return cls(value)

    @staticmethod
    def hex_to_bech32(value: str, prefix: str = "npub") -> str:
        if not _is_hex(value):
            raise KeyError("Expected a 32-byte hex value")
        return _bech32_encode(prefix, bytes.fromhex(value))

    @staticmethod
    def bech32_to_hex(value: str) -> str:
        _, raw = _bech32_decode(value)
        if len(raw) != 32:
            raise KeyError("Expected a 32-byte bech32 payload")
        return raw.hex()

    def private_key_hex(self) -> str | None:
        return self._private.secret.hex() if self._private is not None else None

    def private_key_bech32(self) -> str | None:
        if self._private is None:
            return None
        return _bech32_encode("nsec", self._private.secret)

    def public_key_hex(self) -> str:
        return self._public_hex

    def public_key_bech32(self) -> str:
        return _bech32_encode("npub", bytes.fromhex(self._public_hex))

    @property
    def private_key(self) -> PrivateKey | None:
        return self._private

    def shared_x(self, public_key: str | "Keys") -> bytes:
        if self._private is None:
            raise KeyError("A private key is required for ECDH")
        public_hex = (
            public_key.public_key_hex()
            if isinstance(public_key, Keys)
            else self._decode_public(public_key)
        )
        try:
            point = PublicKey(b"\x02" + bytes.fromhex(public_hex))
            return point.multiply(self._private.secret).format(compressed=True)[1:]
        except Exception as exc:
            raise KeyError("Unable to calculate shared key") from exc
