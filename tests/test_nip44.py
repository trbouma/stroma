import hashlib

import pytest

from stroma import EncryptionError, Keys, NIP44Encrypt, calc_padded_len, pad, unpad


CONVERSATION_KEY = bytes.fromhex(
    "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d"
)
NONCE = bytes.fromhex("00" * 31 + "01")


def test_official_nip44_vector() -> None:
    payload = NIP44Encrypt.encrypt_with_conversation_key(
        "a", CONVERSATION_KEY, nonce=NONCE
    )

    assert payload == (
        "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtD"
        "KfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb"
    )
    assert NIP44Encrypt.decrypt_with_conversation_key(payload, CONVERSATION_KEY) == "a"


def test_conversation_key_is_symmetric() -> None:
    alice = Keys(priv_k="1".zfill(64))
    bob = Keys(priv_k="2".zfill(64))

    assert NIP44Encrypt(alice).conversation_key(bob) == CONVERSATION_KEY
    assert NIP44Encrypt(bob).conversation_key(alice) == CONVERSATION_KEY


@pytest.mark.parametrize("length", [1, 32, 33, 255, 256, 257, 65535, 65536, 65537])
def test_padding_round_trip(length: int) -> None:
    message = "a" * length
    padded = pad(message)

    assert unpad(padded) == message
    prefix = 2 if length < 65536 else 6
    assert len(padded) == prefix + calc_padded_len(length)


@pytest.mark.parametrize(
    ("length", "expected_payload_hash"),
    [
        (65535, "6d8c2810d1e870fbaa1f0a0937126cca837a15f9260e27060c331d70a3c0bc84"),
        (65536, "b7b4edb36ba92e267d322d56d9aebc22e7fa96ff52e3c12adc07f07a43cbc616"),
        (65537, "eeb7c7c5373894ea2c1547cfd3ccb15d5a0b2d619da852e5c79df792dcc9e435"),
    ],
)
def test_official_extended_length_vectors(length: int, expected_payload_hash: str) -> None:
    payload = NIP44Encrypt.encrypt_with_conversation_key(
        "a" * length,
        CONVERSATION_KEY,
        nonce=NONCE,
    )

    assert hashlib.sha256(payload.encode()).hexdigest() == expected_payload_hash
    assert NIP44Encrypt.decrypt_with_conversation_key(payload, CONVERSATION_KEY) == "a" * length


def test_mac_failure_is_rejected() -> None:
    alice = Keys()
    bob = Keys()
    cipher = NIP44Encrypt(alice)
    payload = cipher.encrypt("hello", bob)
    damaged = payload[:-2] + ("AA" if payload[-2:] != "AA" else "BB")

    with pytest.raises(EncryptionError):
        NIP44Encrypt(bob).decrypt(damaged, alice)
