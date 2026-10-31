"""Offline cross-provider checks of PUBLIC TEST fixtures, not a Stroma API.

Uses OpenSSL's default provider (not oqsprovider), cryptography AESGCM and HKDFExpand.
This checks primitives and schedule calculations, not an independent HPKE stack.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand


def der(tag, value):
    n = len(value)
    length = bytes([n]) if n < 128 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag]) + length + value


def check(fixture_path, openssl):
    data = json.loads(Path(fixture_path).read_text())
    keys = {k: bytes.fromhex(v) for k, v in data["keys"].items()}
    # OIDs reported by OpenSSL default provider for ML-DSA-44 and ML-KEM-768.
    sig_alg = der(0x30, der(6, bytes.fromhex("608648016503040311")))
    kem_alg = der(0x30, der(6, bytes.fromhex("608648016503040402")))
    spki = der(0x30, sig_alg + der(3, b"\x00" + keys["signing_public"]))
    seed_key = der(0x30, der(2, b"\x00") + kem_alg + der(4, der(0x80, keys["kem_seed_TEST_ONLY"])))
    env = {**os.environ, "OPENSSL_CONF": os.devnull}

    def run(*args, success=True):
        result = subprocess.run([openssl, *args], env=env, capture_output=True, timeout=15)
        if (result.returncode == 0) != success:
            raise RuntimeError(f"OpenSSL unexpected result for {args[0]}: {result.stderr.decode(errors='replace')}")
        return result.stdout

    print(run("version").decode().strip())
    with tempfile.TemporaryDirectory(prefix="stroma-public-pq-test-") as directory:
        root = Path(directory)

        def put(name, content):
            target = root / name
            target.write_bytes(content)
            return str(target)

        pubfile = put("sign-public.der", spki)
        kemfile = put("kem-PUBLIC-TEST-SEED.der", seed_key)
        expected_spki = der(0x30, kem_alg + der(3, b"\x00" + keys["kem_public"]))
        actual_spki = run("pkey", "-provider", "default", "-in", kemfile, "-inform", "DER", "-pubout", "-outform", "DER")
        if actual_spki != expected_spki:
            raise RuntimeError("OpenSSL/liboqs seed-derived KEM public key mismatch")
        for vector in data["vectors"]:
            v = {k: bytes.fromhex(value) for k, value in vector["hex"].items()}
            transcript = put("transcript.bin", v["transcript"])
            signature = put("signature.bin", v["signature"])

            def verify(ctx, success=True):
                return run("pkeyutl", "-provider", "default", "-verify", "-pubin",
                           "-inkey", pubfile, "-keyform", "DER", "-rawin", "-in", transcript,
                           "-sigfile", signature, "-pkeyopt", "context-string:" + ctx, success=success)

            verify("stroma-pq-v1")
            verify("wrong-context", success=False)
            put("signature.bin", bytes([v["signature"][0] ^ 1]) + v["signature"][1:])
            verify("stroma-pq-v1", success=False)
            encfile = put("enc.bin", v["enc"])
            shared = run("pkeyutl", "-provider", "default", "-decap", "-inkey", kemfile,
                         "-keyform", "DER", "-in", encfile)
            if shared != v["shared_secret"]:
                raise RuntimeError("OpenSSL decapsulation mismatch")
            put("enc.bin", bytes([v["enc"][0] ^ 1]) + v["enc"][1:])
            rejected = run("pkeyutl", "-provider", "default", "-decap", "-inkey", kemfile,
                           "-keyform", "DER", "-in", encfile)
            if rejected == shared:
                raise RuntimeError("invalid encapsulation yielded original secret")

            # Separate implementation of RFC 9180 base-mode schedule using
            # cryptography's HMAC and HKDFExpand, with intermediate comparisons.
            prefix = b"HPKE-v1HPKE" + bytes.fromhex("004100010002")

            def ex(salt, label, ikm):
                h = hmac.HMAC(salt, hashes.SHA256())
                h.update(prefix + label + ikm)
                return h.finalize()

            psk_hash = ex(b"", b"psk_id_hash", b"")
            info_hash = ex(b"", b"info_hash", v["info"])
            context = b"\x00" + psk_hash + info_hash
            secret = ex(shared, b"secret", b"")
            values = {"psk_id_hash": psk_hash, "info_hash": info_hash,
                      "key_schedule_context": context, "secret": secret}
            for field, label, length in (("key", b"key", 32), ("base_nonce", b"base_nonce", 12),
                                         ("exporter_secret", b"exp", 32)):
                values[field] = HKDFExpand(hashes.SHA256(), length,
                    length.to_bytes(2, "big") + prefix + label + context).derive(secret)
            if any(value != v[key] for key, value in values.items()):
                raise RuntimeError("independent schedule calculation mismatch")
            cipher = AESGCM(values["key"])
            if cipher.decrypt(values["base_nonce"], v["ciphertext"], v["aad"]) != v["plaintext"]:
                raise RuntimeError("AES-GCM mismatch")
            if cipher.encrypt(values["base_nonce"], v["plaintext"], v["aad"]) != v["ciphertext"]:
                raise RuntimeError("AES-GCM encryption mismatch")
            print(f"{vector['name']}: signature/context/tamper, KEM/implicit rejection, KDF and AES-GCM passed")
    print("Cross-provider checks passed; independent full-envelope/HPKE validation remains outstanding.")
    print("Fixture SHA-256:", hashlib.sha256(Path(fixture_path).read_bytes()).hexdigest())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--openssl", required=True)
    args = parser.parse_args()
    check(args.fixture, args.openssl)
