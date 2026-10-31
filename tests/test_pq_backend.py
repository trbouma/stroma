"""Default-install safety plus opt-in native integration tests (no network)."""
import ctypes as ct
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import Mock

import pytest

from stroma import pq


def test_import_does_not_import_wrapper_or_load_native():
    code = '''
import sys
import stroma
def audit(event, args):
    if event == "ctypes.dlopen" and args[0] and "oqs" in str(args[0]):
        raise AssertionError("unexpected native load")
    if event in {"subprocess.Popen", "os.system", "socket.connect"}:
        raise AssertionError("unexpected external activity")
sys.addaudithook(audit)
import stroma.pq
assert "oqs" not in sys.modules
assert stroma.Keys().public_key_hex()
'''
    subprocess.run([sys.executable, "-c", code], check=True)


@pytest.mark.parametrize("version", [None, "0.14.0"])
def test_dependency_failure_before_native_load(monkeypatch, version):
    def lookup(_):
        if version is None:
            raise pq.metadata.PackageNotFoundError()
        return version
    monkeypatch.setattr(pq.metadata, "version", lookup)
    loader = Mock()
    monkeypatch.setattr(pq.ct, "CDLL", loader)
    with pytest.raises(pq.PQBackendUnavailable):
        pq.PQBackend("/missing/liboqs.so")
    loader.assert_not_called()


def test_bad_paths_fail_closed(monkeypatch, tmp_path):
    monkeypatch.setattr(pq.metadata, "version", lambda _: pq.WRAPPER_VERSION)
    for path in ("liboqs.so", tmp_path / "missing", tmp_path):
        with pytest.raises(pq.PQBackendUnavailable):
            pq.PQBackend(path)


def test_wrong_native_version(monkeypatch):
    monkeypatch.setattr(pq.metadata, "version", lambda _: pq.WRAPPER_VERSION)
    native = Mock()
    native.OQS_version.return_value = b"0.14.0"
    monkeypatch.setattr(pq.ct, "CDLL", lambda _: native)
    with pytest.raises(pq.PQBackendUnavailable, match="native liboqs"):
        pq.PQBackend(Path(__file__).resolve())
    native.OQS_init.assert_not_called()


def test_missing_algorithm_symbols(monkeypatch):
    monkeypatch.setattr(pq.metadata, "version", lambda _: pq.WRAPPER_VERSION)
    native = Mock(spec=["OQS_version"])
    native.OQS_version.return_value = pq.NATIVE_VERSION.encode()
    monkeypatch.setattr(pq.ct, "CDLL", lambda _: native)
    with pytest.raises(pq.PQBackendUnavailable, match="enabled"):
        pq.PQBackend(Path(__file__).resolve())


def test_malformed_inputs_never_reach_native():
    backend = object.__new__(pq.PQBackend)
    backend._lib = Mock()
    cases = [
        lambda: backend.sign(b"a", b"", context=b""),
        lambda: backend.sign(b"a", bytes(2560), context=bytes(256)),
        lambda: backend.sign(bytes(pq.MAX_MESSAGE_BYTES + 1), bytes(2560), context=b""),
        lambda: backend.sign("a", bytes(2560), context=b""),
        lambda: backend.verify(b"a", b"", bytes(1312), context=b""),
        lambda: backend.verify(b"a", bytes(2420), b"", context=b""),
        lambda: backend.encapsulate(b""),
        lambda: backend.decapsulate(b"", bytes(2400)),
        lambda: backend.decapsulate(bytes(1088), b""),
    ]
    for case in cases:
        with pytest.raises((ValueError, TypeError)):
            case()
    assert not backend._lib.mock_calls


def test_native_failure_is_not_success():
    backend = object.__new__(pq.PQBackend)
    backend._lib = Mock()
    backend._lib.OQS_KEM_ml_kem_768_encaps.return_value = -1
    with pytest.raises(pq.PQOperationError):
        backend.encapsulate(bytes(1184))


def test_secret_not_in_repr():
    assert "secret-example" not in repr(pq.PQKeyPair(b"public", b"secret-example"))


@pytest.fixture
def backend():
    path = os.environ.get("STROMA_TEST_LIBOQS")
    if not path:
        pytest.skip("Set STROMA_TEST_LIBOQS to explicitly enable native PQ tests")
    return pq.PQBackend(path)


def test_native_roundtrips_and_tampering(backend):
    signing = backend.generate_signing_keypair()
    kem = backend.generate_kem_keypair()
    for message, context in ((b"", b""), (b"hello", b"stroma-pq-v1")):
        signature = backend.sign(message, signing.secret_key, context=context)
        assert backend.verify(message, signature, signing.public_key, context=context)
        assert not backend.verify(message + b"x", signature, signing.public_key, context=context)
        assert not backend.verify(message, signature, signing.public_key, context=b"wrong")
    enc, shared = backend.encapsulate(kem.public_key)
    assert backend.decapsulate(enc, kem.secret_key) == shared
    assert backend.decapsulate(bytes([enc[0] ^ 1]) + enc[1:], kem.secret_key) != shared
    other = backend.generate_kem_keypair()
    assert backend.decapsulate(enc, other.secret_key) != shared


def test_native_fixtures(backend):
    data = json.loads((Path(__file__).parent / "pq_vectors/stroma-pq-v1.json").read_text())
    keys = {k: bytes.fromhex(v) for k, v in data["keys"].items()}
    # Seed regeneration is test-only; never expose deterministic RNG in the adapter.
    function = backend._lib.OQS_KEM_ml_kem_768_keypair_derand
    function.argtypes, function.restype = [ct.c_void_p] * 3, ct.c_int
    public, secret = ct.create_string_buffer(1184), ct.create_string_buffer(2400)
    try:
        assert function(public, secret, keys["kem_seed_TEST_ONLY"]) == 0
        assert public.raw == keys["kem_public"]
        for vector in data["vectors"]:
            v = {k: bytes.fromhex(value) for k, value in vector["hex"].items()}
            assert backend.verify(v["transcript"], v["signature"], keys["signing_public"], context=b"stroma-pq-v1")
            assert backend.decapsulate(v["enc"], secret.raw) == v["shared_secret"]
    finally:
        ct.memset(secret, 0, 2400)
