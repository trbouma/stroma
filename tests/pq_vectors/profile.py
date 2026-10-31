"""Small test-only encoder and HPKE key schedule, NOT a production API."""
import hashlib
import hmac

from Crypto.Cipher import AES

SUITE = b"HPKE" + bytes.fromhex("004100010002")
SIGN_CONTEXT = b"stroma-pq-v1"


def cbor(value):
    def head(major, n):
        if n < 24:
            return bytes([major * 32 + n])
        for size, marker in ((1, 24), (2, 25), (4, 26), (8, 27)):
            if n < 1 << (size * 8):
                return bytes([major * 32 + marker]) + n.to_bytes(size, "big")
        raise ValueError("integer too large")

    if type(value) is int and value >= 0:
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("ascii")
        return head(3, len(raw)) + raw
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(cbor(v) for v in value)
    raise ValueError("unsupported test CBOR type")


def kid(descriptor):
    return hashlib.sha256(cbor(["stroma-pq-key-v1", descriptor])).digest()


def extract(salt, ikm):
    return hmac.digest(salt, ikm, "sha256")


def expand(prk, info, length):
    if not 0 <= length <= 255 * 32:
        raise ValueError("invalid HKDF length")
    result, previous = b"", b""
    for counter in range(1, (length + 31) // 32 + 1):
        previous = hmac.digest(prk, previous + info + bytes([counter]), "sha256")
        result += previous
    return result[:length]


def schedule(shared, info):
    """RFC 9180 base mode, fixed suite, empty PSK and PSK ID."""
    def le(salt, label, ikm):
        return extract(salt, b"HPKE-v1" + SUITE + label + ikm)

    def lx(secret, label, context, n):
        return expand(secret, n.to_bytes(2, "big") + b"HPKE-v1" + SUITE + label + context, n)

    psk_hash = le(b"", b"psk_id_hash", b"")
    info_hash = le(b"", b"info_hash", info)
    context = b"\x00" + psk_hash + info_hash
    secret = le(shared, b"secret", b"")
    return {
        "psk_id_hash": psk_hash,
        "info_hash": info_hash,
        "key_schedule_context": context,
        "secret": secret,
        "key": lx(secret, b"key", context, 32),
        "base_nonce": lx(secret, b"base_nonce", context, 12),
        "exporter_secret": lx(secret, b"exp", context, 32),
    }


def seal(key, nonce, aad, plaintext):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext + tag


def open_ciphertext(key, nonce, aad, ciphertext):
    if len(ciphertext) < 16:
        raise ValueError("truncated tag")
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
    cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext[:-16], ciphertext[-16:])
