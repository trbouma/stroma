"""Isolated compatibility probe. PUBLIC fixtures only; not a production loader.

Run in a fresh interpreter: the audit hook deliberately survives until exit.
The historical wrapper's automatic installer must never run in an application.
"""
import argparse
import ctypes
import ctypes.util
import importlib.metadata
import json
from pathlib import Path
import sys
from unittest.mock import patch


VERSION = "0.14.0"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def check(library, fixture):
    # Resolve/check before importing oqs, which otherwise attempts installation.
    path = Path(library).resolve(strict=True)
    require(importlib.metadata.version("liboqs-python") == VERSION,
            "Expected pinned test wrapper 0.14.0")
    native = ctypes.CDLL(str(path))
    native.OQS_version.restype = ctypes.c_char_p
    require(native.OQS_version().decode() == VERSION,
            "Expected native liboqs 0.14.0; refusing wrapper import")

    def audit(event, args):
        if event in {"subprocess.Popen", "os.system", "os.posix_spawn"} or event.startswith("socket."):
            raise RuntimeError("Network/process execution forbidden in wrapper probe")

    sys.addaudithook(audit)

    def load_exact(name):
        require(Path(name).name in {"liboqs.dylib", "liboqs.so", "oqs.dll"},
                "Unexpected native library request")
        return native

    # Test-only injection avoids platform discovery and upstream auto-install.
    # This does NOT approve upstream's unmodified loader for production use.
    with patch.object(ctypes.util, "find_library", return_value=None), \
         patch.object(ctypes.cdll, "LoadLibrary", side_effect=load_exact):
        import oqs

    require(oqs.native() is native, "Wrapper did not use explicit native handle")
    data = json.loads(Path(fixture).read_text())
    keys = {k: bytes.fromhex(v) for k, v in data["keys"].items()}
    context = b"stroma-pq-v1"
    with oqs.KeyEncapsulation("ML-KEM-768") as kem, oqs.Signature("ML-DSA-44") as sig:
        require(kem.generate_keypair_seed(keys["kem_seed_TEST_ONLY"]) == keys["kem_public"],
                "Seed-derived public key mismatch")
        for vector in data["vectors"]:
            v = {k: bytes.fromhex(value) for k, value in vector["hex"].items()}
            verify = lambda s, c: sig.verify_with_ctx_str(v["transcript"], s, c, keys["signing_public"])
            require(verify(v["signature"], context), "Fixture signature rejected")
            require(not verify(v["signature"], b"wrong-context"), "Wrong context accepted")
            altered = bytes([v["signature"][0] ^ 1]) + v["signature"][1:]
            require(not verify(altered, context), "Altered signature accepted")
            require(kem.decap_secret(v["enc"]) == v["shared_secret"], "Decapsulation mismatch")
            altered = bytes([v["enc"][0] ^ 1]) + v["enc"][1:]
            require(kem.decap_secret(altered) != v["shared_secret"], "Implicit rejection failed")
            print(vector["name"] + ": wrapper fixture checks passed")

        public = sig.generate_keypair()
        signature = sig.sign_with_ctx_str(b"disposable wrapper test", context)
        require(sig.verify_with_ctx_str(b"disposable wrapper test", signature, context, public),
                "Fresh signature round trip failed")
        enc, shared = kem.encap_secret(keys["kem_public"])
        require(kem.decap_secret(enc) == shared, "Fresh KEM round trip failed")
    print("Pinned wrapper/native compatibility passed; production loader remains a release gate.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture")
    parser.add_argument("--liboqs", required=True)
    args = parser.parse_args()
    try:
        check(args.liboqs, args.fixture)
    except (OSError, RuntimeError, importlib.metadata.PackageNotFoundError) as exc:
        parser.exit(1, f"Backend probe failed: {exc}\n")
