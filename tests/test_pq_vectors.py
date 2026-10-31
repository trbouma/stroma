"""Offline framing/KDF/AEAD fixtures, without a PQ runtime dependency."""
import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).parent / "pq_vectors"
spec = importlib.util.spec_from_file_location("pq_fixture_profile", ROOT / "profile.py")
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
DATA = json.loads((ROOT / "stroma-pq-v1.json").read_text())


def test_rfc5869_case_one():
    prk = p.extract(bytes(range(13)), b"\x0b" * 22)
    assert prk.hex() == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    assert p.expand(prk, bytes(range(0xf0, 0xfa)), 42).hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865")


@pytest.mark.parametrize("value,encoded", [(0, "00"), (24, "1818"), (256, "190100"),
    (b"", "40"), ("a", "6161"), ([1, b"ab"], "8201426162")])
def test_canonical_encoding_examples(value, encoded):
    assert p.cbor(value).hex() == encoded


@pytest.mark.parametrize("value", [True, None, -1, {}, 1.0])
def test_encoder_rejects_out_of_profile_types(value):
    with pytest.raises(ValueError):
        p.cbor(value)


@pytest.mark.parametrize("vector", DATA["vectors"], ids=lambda v: v["name"])
def test_fixture_transcripts_and_ciphertext(vector):
    v = {k: bytes.fromhex(value) for k, value in vector["hex"].items()}
    keys = {k: bytes.fromhex(value) for k, value in DATA["keys"].items()}
    ds = p.cbor([1, "sign", "ML-DSA-44", keys["signing_public"]])
    dk = p.cbor([1, "kem", "ML-KEM-768", keys["kem_public"]])
    assert ds == keys["signing_descriptor"] and dk == keys["kem_descriptor"]
    assert v["header"] == p.cbor([1, 1, 1, "private-record", p.kid(ds), p.kid(dk),
                                   v["message_id"], v["context"]])
    assert v["transcript"] == p.cbor(["stroma-pq-sign-v1", v["header"], v["payload"]])
    assert v["info"] == p.cbor(["stroma-pq-hpke-v1", v["header"]])
    assert v["aad"] == p.cbor(["stroma-pq-aad-v1", v["header"], v["enc"]])
    assert v["plaintext"] == p.cbor([v["payload"], v["signature"]])
    assert len(v["signature"]) == 2420 and len(v["enc"]) == 1088
    assert all(value == v[name] for name, value in p.schedule(v["shared_secret"], v["info"]).items())
    assert p.seal(v["key"], v["base_nonce"], v["aad"], v["plaintext"]) == v["ciphertext"]
    assert p.open_ciphertext(v["key"], v["base_nonce"], v["aad"], v["ciphertext"]) == v["plaintext"]
    assert v["envelope"] == p.cbor([v["header"], v["enc"], v["ciphertext"]])


@pytest.mark.parametrize("field", ["key", "base_nonce", "aad", "ciphertext"])
def test_aead_tampering_rejected(field):
    v = {k: bytes.fromhex(value) for k, value in DATA["vectors"][0]["hex"].items()}
    v[field] = bytes([v[field][0] ^ 1]) + v[field][1:]
    with pytest.raises(ValueError):
        p.open_ciphertext(v["key"], v["base_nonce"], v["aad"], v["ciphertext"])


def test_truncated_tag_rejected():
    with pytest.raises(ValueError):
        p.open_ciphertext(bytes(32), bytes(12), b"", bytes(15))
