"""Disposable deterministic PQ vector generator. Run only as a separate process.

Loads an explicitly supplied existing native library; no oqs Python import,
automatic installation, wallet configuration, application keys or network I/O.
ALL randomness and key material in these fixtures is PUBLIC TEST DATA.
"""
import argparse
import ctypes as ct
import hashlib
import json
from pathlib import Path

from profile import SIGN_CONTEXT, cbor, kid, schedule, seal


def generate(library):
    lib = ct.CDLL(str(Path(library).resolve(strict=True)))
    lib.OQS_version.restype = ct.c_char_p
    pointer, size = ct.c_void_p, ct.c_size_t
    signatures = {
        "OQS_SIG_ml_dsa_44_keypair": [pointer, pointer],
        "OQS_SIG_ml_dsa_44_sign_with_ctx_str": [pointer, pointer, pointer, size, pointer, size, pointer],
        "OQS_SIG_ml_dsa_44_verify_with_ctx_str": [pointer, size, pointer, size, pointer, size, pointer],
        "OQS_KEM_ml_kem_768_keypair_derand": [pointer, pointer, pointer],
        "OQS_KEM_ml_kem_768_encaps": [pointer, pointer, pointer],
        "OQS_KEM_ml_kem_768_decaps": [pointer, pointer, pointer],
    }
    for name, args in signatures.items():
        function = getattr(lib, name)
        function.argtypes, function.restype = args, ct.c_int

    # This hook is global to liboqs: this script must remain process-isolated.
    rng_type = ct.CFUNCTYPE(None, pointer, size)
    label, offset, requests = b"", 0, []

    @rng_type
    def test_rng(destination, n):
        nonlocal offset
        stream = hashlib.shake_256(b"stroma-pq-PUBLIC-TEST-ONLY/" + label).digest(offset + n)
        ct.memmove(destination, stream[offset:], n)
        offset += n
        requests.append(n)

    lib.OQS_randombytes_custom_algorithm.argtypes = [rng_type]
    lib.OQS_randombytes_custom_algorithm.restype = None
    lib.OQS_randombytes_switch_algorithm.argtypes = [ct.c_char_p]
    lib.OQS_randombytes_switch_algorithm.restype = ct.c_int

    def rng(stage):
        nonlocal label, offset, requests
        label, offset, requests = stage.encode("ascii"), 0, []

    def call(name, *args):
        if getattr(lib, name)(*args) != 0:
            raise RuntimeError(f"native test operation failed: {name}")

    pk, sk = ct.create_string_buffer(1312), ct.create_string_buffer(2560)
    kem_pk, kem_sk = ct.create_string_buffer(1184), ct.create_string_buffer(2400)
    seed = bytes(range(64))
    lib.OQS_randombytes_custom_algorithm(test_rng)
    try:
        rng("signature-keygen")
        call("OQS_SIG_ml_dsa_44_keypair", pk, sk)
        keygen_requests = list(requests)
        call("OQS_KEM_ml_kem_768_keypair_derand", kem_pk, kem_sk, seed)
        ds = cbor([1, "sign", "ML-DSA-44", pk.raw])
        dk = cbor([1, "kem", "ML-KEM-768", kem_pk.raw])
        fixtures = []
        for name, payload, context in (
            ("record", b"Disposable private record: hello Stroma", b"record:example;revision:1"),
            ("empty", b"", b""),
        ):
            message_id = hashlib.sha256(name.encode()).digest()[:16]
            header = cbor([1, 1, 1, "private-record", kid(ds), kid(dk), message_id, context])
            transcript = cbor(["stroma-pq-sign-v1", header, payload])
            sig, siglen = ct.create_string_buffer(2420), size()
            rng(name + "/signature")
            call("OQS_SIG_ml_dsa_44_sign_with_ctx_str", sig, ct.byref(siglen),
                 transcript, len(transcript), SIGN_CONTEXT, len(SIGN_CONTEXT), sk)
            if siglen.value != 2420:
                raise RuntimeError("unexpected signature length")
            sign_requests = list(requests)
            call("OQS_SIG_ml_dsa_44_verify_with_ctx_str", transcript, len(transcript),
                 sig, siglen.value, SIGN_CONTEXT, len(SIGN_CONTEXT), pk)
            enc, shared, recovered = (ct.create_string_buffer(n) for n in (1088, 32, 32))
            rng(name + "/encapsulation")
            call("OQS_KEM_ml_kem_768_encaps", enc, shared, kem_pk)
            enc_requests = list(requests)
            call("OQS_KEM_ml_kem_768_decaps", recovered, enc, kem_sk)
            if shared.raw != recovered.raw:
                raise RuntimeError("KEM shared secret mismatch")
            info = cbor(["stroma-pq-hpke-v1", header])
            aad = cbor(["stroma-pq-aad-v1", header, enc.raw])
            plaintext = cbor([payload, sig.raw])
            state = schedule(shared.raw, info)
            ciphertext = seal(state["key"], state["base_nonce"], aad, plaintext)
            fields = dict(payload=payload, context=context, message_id=message_id,
                          header=header, transcript=transcript, signature=sig.raw,
                          enc=enc.raw, shared_secret=shared.raw, info=info, aad=aad,
                          plaintext=plaintext, ciphertext=ciphertext,
                          envelope=cbor([header, enc.raw, ciphertext]), **state)
            fixtures.append({"name": name, "hex": {k: v.hex() for k, v in fields.items()},
                             "rng_requests": {"sign": sign_requests, "encap": enc_requests}})
        return {"warning": "PUBLIC TEST KEYS AND SECRETS. NEVER USE FOR REAL DATA.",
                "profile": "stroma-pq-v1", "generator_liboqs": lib.OQS_version().decode(),
                "rng": "SHAKE256(stroma-pq-PUBLIC-TEST-ONLY/ || stage), sequential bytes",
                "signature_keygen_rng_requests": keygen_requests,
                "keys": {"signing_public": pk.raw.hex(), "kem_public": kem_pk.raw.hex(),
                         "kem_seed_TEST_ONLY": seed.hex(), "signing_descriptor": ds.hex(),
                         "kem_descriptor": dk.hex()}, "vectors": fixtures}
    finally:
        # No private signing/expanded KEM key serialization is needed.
        ct.memset(sk, 0, len(sk))
        ct.memset(kem_sk, 0, len(kem_sk))
        if lib.OQS_randombytes_switch_algorithm(b"system") != 0:
            raise RuntimeError("unable to restore liboqs system RNG")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--liboqs", required=True, help="Existing native library; never downloaded")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    data = generate(args.liboqs)
    args.output.write_text(json.dumps(data, indent=2) + "\n")
    print(f"Generated {len(data['vectors'])} PUBLIC TEST fixtures using liboqs {data['generator_liboqs']}")
