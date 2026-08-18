"""NIP-44 version 2 encryption, including the extended length prefix."""

from __future__ import annotations

import base64
import hashlib
import hmac
import math
import secrets

from Crypto.Cipher import ChaCha20

from .errors import EncryptionError
from .keys import Keys

VERSION = 2
MIN_PLAINTEXT_SIZE = 1
EXTENDED_PREFIX_THRESHOLD = 65536
PROTOCOL_MAX_PLAINTEXT_SIZE = (1 << 32) - 1
DEFAULT_MAX_PLAINTEXT_SIZE = 262143


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    output = b""
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(prk, previous + info + bytes((counter,)), hashlib.sha256).digest()
        output += previous
        counter += 1
    return output[:length]


def calc_padded_len(unpadded_len: int) -> int:
    if unpadded_len < 1:
        raise EncryptionError("Plaintext must not be empty")
    next_power = 32 if unpadded_len <= 1 else 1 << ((unpadded_len - 1).bit_length())
    chunk = 32 if next_power <= 256 else next_power // 8
    return 32 if unpadded_len <= 32 else chunk * math.ceil(unpadded_len / chunk)


def _prefix_length(unpadded_len: int) -> int:
    return 2 if unpadded_len < EXTENDED_PREFIX_THRESHOLD else 6


def pad(plaintext: str, *, max_plaintext_size: int = DEFAULT_MAX_PLAINTEXT_SIZE) -> bytes:
    raw = plaintext.encode("utf-8")
    length = len(raw)
    if not MIN_PLAINTEXT_SIZE <= length <= min(max_plaintext_size, PROTOCOL_MAX_PLAINTEXT_SIZE):
        raise EncryptionError(f"Plaintext length {length} is outside the configured limit")
    if length < EXTENDED_PREFIX_THRESHOLD:
        prefix = length.to_bytes(2, "big")
    else:
        prefix = b"\x00\x00" + length.to_bytes(4, "big")
    return prefix + raw + bytes(calc_padded_len(length) - length)


def unpad(padded: bytes, *, max_plaintext_size: int = DEFAULT_MAX_PLAINTEXT_SIZE) -> str:
    if len(padded) < 2:
        raise EncryptionError("Invalid NIP-44 padding")
    short_length = int.from_bytes(padded[:2], "big")
    if short_length == 0:
        if len(padded) < 6:
            raise EncryptionError("Invalid extended NIP-44 prefix")
        length = int.from_bytes(padded[2:6], "big")
        prefix_length = 6
        if length < EXTENDED_PREFIX_THRESHOLD:
            raise EncryptionError("Non-canonical extended NIP-44 prefix")
    else:
        length = short_length
        prefix_length = 2
    if not MIN_PLAINTEXT_SIZE <= length <= min(max_plaintext_size, PROTOCOL_MAX_PLAINTEXT_SIZE):
        raise EncryptionError("Plaintext length is outside the configured limit")
    raw = padded[prefix_length : prefix_length + length]
    if len(raw) != length or len(padded) != prefix_length + calc_padded_len(length):
        raise EncryptionError("Invalid NIP-44 padding")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise EncryptionError("NIP-44 plaintext is not UTF-8") from exc


class NIP44Encrypt:
    """NIP-44 v2 using an application-configurable resource ceiling."""

    def __init__(self, key: Keys | str, *, max_plaintext_size: int = DEFAULT_MAX_PLAINTEXT_SIZE) -> None:
        self.keys = key if isinstance(key, Keys) else Keys(priv_k=key)
        if self.keys.private_key_hex() is None:
            raise EncryptionError("NIP-44 requires a private key")
        if not MIN_PLAINTEXT_SIZE <= max_plaintext_size <= PROTOCOL_MAX_PLAINTEXT_SIZE:
            raise EncryptionError("Invalid maximum plaintext size")
        self.max_plaintext_size = max_plaintext_size

    def conversation_key(self, public_key: str | Keys) -> bytes:
        return _hkdf_extract(b"nip44-v2", self.keys.shared_x(public_key))

    @staticmethod
    def message_keys(conversation_key: bytes, nonce: bytes) -> tuple[bytes, bytes, bytes]:
        if len(conversation_key) != 32 or len(nonce) != 32:
            raise EncryptionError("Conversation key and nonce must be 32 bytes")
        material = _hkdf_expand(conversation_key, nonce, 76)
        return material[:32], material[32:44], material[44:]

    @staticmethod
    def encrypt_with_conversation_key(
        plaintext: str,
        conversation_key: bytes,
        *,
        nonce: bytes | None = None,
        max_plaintext_size: int = DEFAULT_MAX_PLAINTEXT_SIZE,
    ) -> str:
        nonce = secrets.token_bytes(32) if nonce is None else nonce
        chacha_key, chacha_nonce, hmac_key = NIP44Encrypt.message_keys(conversation_key, nonce)
        padded = pad(plaintext, max_plaintext_size=max_plaintext_size)
        ciphertext = ChaCha20.new(key=chacha_key, nonce=chacha_nonce).encrypt(padded)
        mac = hmac.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
        return base64.b64encode(bytes((VERSION,)) + nonce + ciphertext + mac).decode("ascii")

    @staticmethod
    def decrypt_with_conversation_key(
        payload: str,
        conversation_key: bytes,
        *,
        max_plaintext_size: int = DEFAULT_MAX_PLAINTEXT_SIZE,
    ) -> str:
        if payload.startswith("#"):
            raise EncryptionError("Unsupported NIP-44 encoding")
        if len(payload) < 132:
            raise EncryptionError("NIP-44 payload is too short")
        maximum_padded = calc_padded_len(max_plaintext_size) + _prefix_length(max_plaintext_size)
        maximum_raw = 1 + 32 + maximum_padded + 32
        maximum_base64 = 4 * math.ceil(maximum_raw / 3)
        if len(payload) > maximum_base64:
            raise EncryptionError("NIP-44 payload exceeds the configured limit")
        try:
            decoded = base64.b64decode(payload, validate=True)
        except Exception as exc:
            raise EncryptionError("Invalid NIP-44 base64 payload") from exc
        if len(decoded) < 99 or decoded[0] != VERSION:
            raise EncryptionError("Unsupported or malformed NIP-44 payload")
        nonce, ciphertext, supplied_mac = decoded[1:33], decoded[33:-32], decoded[-32:]
        chacha_key, chacha_nonce, hmac_key = NIP44Encrypt.message_keys(conversation_key, nonce)
        calculated_mac = hmac.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(calculated_mac, supplied_mac):
            raise EncryptionError("Invalid NIP-44 MAC")
        padded = ChaCha20.new(key=chacha_key, nonce=chacha_nonce).decrypt(ciphertext)
        return unpad(padded, max_plaintext_size=max_plaintext_size)

    def encrypt(
        self,
        plain_text: str,
        to_pub_k: str | Keys,
        version: int = VERSION,
        *,
        nonce: bytes | None = None,
    ) -> str:
        if version != VERSION:
            raise EncryptionError(f"Unsupported NIP-44 version: {version}")
        return self.encrypt_with_conversation_key(
            plain_text,
            self.conversation_key(to_pub_k),
            nonce=nonce,
            max_plaintext_size=self.max_plaintext_size,
        )

    def decrypt(self, payload: str, for_pub_k: str | Keys) -> str:
        return self.decrypt_with_conversation_key(
            payload,
            self.conversation_key(for_pub_k),
            max_plaintext_size=self.max_plaintext_size,
        )
