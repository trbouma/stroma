# Experimental PQ envelope fixtures

These are offline, disposable test fixtures for the proposed `stroma-pq-v1`
profile. **Every key seed, shared secret, derived key and nonce here is public
test data. Never use these fixtures to protect real information.** The generator
does not read wallets, service secrets or application configuration.

## Contents and scope

- `stroma-pq-v1.json`: two deterministic fixtures (record payload and empty payload),
  public descriptors, canonical transcripts, signatures, encapsulations, shared
  secrets, HPKE intermediate values, AES-GCM output and complete binary envelopes.
- `profile.py`: test-only canonical encoder and RFC 9180 base-mode key schedule.
  It is not a production envelope parser or API.
- `generate.py`: explicit native liboqs fixture generation in a separate process.
- `check_openssl.py`: OpenSSL default-provider signature/KEM checks and a second
  implementation of schedule calculations and AES-GCM using `cryptography`.
- `../test_pq_vectors.py`: normal offline regression tests, requiring no PQ backend.

The JSON records its generation library version and test-RNG request sizes.
Signature key generation and per-message randomness use explicitly labeled SHAKE256
streams solely inside the generator process. The KEM key seed is public bytes 0–63.
Randomized ML-DSA signing is exercised with reproducible test randomness, not the
deterministic-signing mode. Expanded private keys are not saved. Regeneration with
the recorded library version must produce identical bytes; different native versions
may change random-byte consumption and require reviewed fixture updates.

## Run ordinary fixture checks

From the repository root:

```console
poetry run pytest -q tests/test_pq_vectors.py
```

These checks cover canonical encoding examples, RFC 5869 test case 1, reconstructed
Stroma transcripts, HPKE schedule intermediates, encryption/decryption, altered
key/nonce/AAD/ciphertext and truncated-tag rejection. They do not independently
verify PQ signatures; run the cross-provider checker for that evidence.

## Regenerate with an existing native library

```console
poetry run python tests/pq_vectors/generate.py \
  --liboqs /absolute/path/to/liboqs.dylib \
  --output /tmp/stroma-pq-v1.json
cmp tests/pq_vectors/stroma-pq-v1.json /tmp/stroma-pq-v1.json
```

Use the appropriate `.so`/`.dll` path on other platforms. Nothing is downloaded
or compiled automatically. The generator calls the native fixed-algorithm C APIs
directly, avoiding installed Python-wrapper/native ABI mismatches. It requires the
specific symbols used in the script; it is not a supported general liboqs binding.
Missing symbols fail explicitly. Its global test RNG must never run in a server,
shared worker or production process. No deterministic RNG interface is added to
`src/stroma` and no distribution dependency is changed.

## Cross-provider verification

Use a separate test interpreter with `cryptography` installed and an OpenSSL CLI
whose default provider supports ML-DSA-44 and ML-KEM-768:

```console
python tests/pq_vectors/check_openssl.py \
  tests/pq_vectors/stroma-pq-v1.json \
  --openssl /absolute/path/to/openssl
```

The checker disables user OpenSSL configuration and explicitly selects the default
provider, not oqsprovider. It verifies liboqs signatures, rejects altered signatures
and wrong signing contexts, regenerates the KEM public key from the public test seed,
decapsulates the fixture and checks altered encapsulation implicit rejection.
It compares KDF intermediates through `cryptography` HMAC/HKDFExpand and AES-GCM
through its OpenSSL backend. Temporary test-only files are removed on exit.

## Recorded validation

### Optional Python wrapper compatibility probe

`check_wrapper.py` tests the historical wrapper/native **0.14.0** pair in a
separate interpreter. The wrapper is pinned to upstream commit
`d552e3a55985e5a2396545d744be0a01321ddbc3`; there is no corresponding published
PyPI release or Git tag. This is a reproducibility pin, **not a recommended
production dependency**. Install only into a disposable environment:

```console
python3.12 -m venv /tmp/stroma-pq-wrapper-check
/tmp/stroma-pq-wrapper-check/bin/pip install \
  'liboqs-python @ git+https://github.com/open-quantum-safe/liboqs-python.git@d552e3a55985e5a2396545d744be0a01321ddbc3'
/tmp/stroma-pq-wrapper-check/bin/python tests/pq_vectors/check_wrapper.py \
  tests/pq_vectors/stroma-pq-v1.json --liboqs /absolute/path/to/liboqs.dylib
```

On 2026-10-31 this passed both fixtures, wrong-context/tampered-signature rejection,
KEM implicit rejection, and fresh randomized signature/KEM round trips on macOS.
Missing native library and absent wrapper checks exited with explicit errors.
Offline regression tests additionally check version mismatches before wrapper import.

The upstream loader attempts to download/build liboqs if it cannot find a library;
an environment search path alone does not disable that behavior. This probe checks
versions before import, injects the explicit native handle into the wrapper loader,
and installs a process-local audit hook rejecting network/process execution. Those
test-only patches are **not** a production loader or a general native-code sandbox.
The historical installer uses shell execution; do not deploy it unmodified.

Before shipping an optional provider, choose maintained wrapper/native release pins,
repeat these tests, and provide an explicit no-install loader (upstream support or a
reviewed adapter). Missing, unloadable, mismatched or unsupported native libraries
must fail closed without downloading, compiling or selecting another algorithm.
Successful wrapper tests do not independently validate HPKE or the envelope parser.

### Cross-provider fixture results

On 2026-10-31, fixtures were generated with liboqs 0.14.0 and reproduced byte-for-byte.
Cross-provider checks passed using OpenSSL CLI 3.6.3 and cryptography 46.0.3
(OpenSSL backend 3.5.4). These are observed test versions, not production dependency
approval or FIPS module validation. Fixture SHA-256:

```text
08c28a18a7e5199d8daf7be2cdfb2f6378a368db054dcaf0b1e3c7fcedf56e9d
```

This establishes cross-provider primitive compatibility and matching schedule
calculations. It does **not** establish conformance against an independent full
HPKE implementation or independently written Stroma envelope reader. That remains
a release gate, along with strict-decoder malformed-input cases, size boundaries,
key rotation/recovery, replay-state enforcement, downgrade handling and concurrency.
The committed fixture format is experimental and does not replace external vectors
from FIPS/ACVP or the pinned HPKE specifications.
