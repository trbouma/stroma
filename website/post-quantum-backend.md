# Optional Post Quantum Backend

Stroma offers experimental ML-DSA-44 signatures and ML-KEM-768 key establishment
through `stroma.pq`. This is a primitive adapter, not the proposed HPKE envelope
or a production security certification. Existing Nostr features are unchanged.

## Installation

The distribution is `stroma-nostr`; the Python import is `stroma`.

```sh
pip install stroma-nostr
pip install 'stroma-nostr[pq]'
```

For repository versions, replace `COMMIT_SHA` with a full reviewed commit:

```sh
pip install 'stroma-nostr @ git+https://github.com/trbouma/stroma.git@COMMIT_SHA'
pip install 'stroma-nostr[pq] @ git+https://github.com/trbouma/stroma.git@COMMIT_SHA'
```

The default install has no PQ dependency. The extra pins `liboqs-python` to
**0.16.0.2**, also used for compatibility testing. Provision native **liboqs 0.16.0**
separately with ML-DSA-44 and ML-KEM-768 enabled. Keep other applications' native
installations separate unless their compatibility has been checked.

The adapter checks the extra's package version but deliberately does **not** import
`oqs`: upstream's loader can install native code on import. Stroma instead binds
only the required C functions using `ctypes` and an absolute library path. There
is no automatic search, download, build, algorithm fallback or global loader patch.
This narrow binding is part of the code requiring independent review.

Importing `stroma` or `stroma.pq` never loads liboqs. Construction raises
`PQBackendUnavailable` for absent/mismatched dependencies, unloadable libraries or
missing algorithm symbols. Only use operator-controlled paths: loading native
code executes it before its version can be checked.

## Primitive API

```python
from stroma.pq import PQBackend

pq = PQBackend('/absolute/path/to/liboqs.dylib')  # .so or .dll on other platforms
signing = pq.generate_signing_keypair()
signature = pq.sign(b'example', signing.secret_key, context=b'my-app-v1')
assert pq.verify(b'example', signature, signing.public_key, context=b'my-app-v1')

recipient = pq.generate_kem_keypair()
encapsulation, sender_secret = pq.encapsulate(recipient.public_key)
recipient_secret = pq.decapsulate(encapsulation, recipient.secret_key)
assert sender_secret == recipient_secret
```

Signing uses randomized ordinary ML-DSA, not prehash mode. Context is mandatory
as a keyword, may be empty, and is limited to 255 bytes. Messages are limited to
1 MiB at this primitive layer. Inputs must be `bytes` with exact fixed key,
signature and encapsulation lengths. Malformed inputs raise `TypeError` or
`ValueError`; invalid signatures return `False`; native failures raise
`PQOperationError`. No algorithm selector is exposed.

ML-KEM implicit rejection can return a different secret for an invalid
encapsulation without raising an error. Decapsulation alone is not authentication.
Never use the raw secret directly as an encryption key: use a reviewed protocol
with KDF, authenticated encryption and sender authentication. The proposed Stroma
envelope has not yet been implemented or independently validated.

## Key handling and concurrency

Key pairs contain raw public and secret bytes. Secret fields are excluded from
their representation; callers must still prevent logging and provide secure
storage, rotation and recovery. Temporary native secret buffers are cleared, but
Python immutable byte copies cannot be reliably erased.

Calls are synchronous and serialized within the adapter. Async applications can
use `asyncio.to_thread` with their own queue limits. Do not share the process with
code that overrides liboqs's global RNG or calls global teardown during operations.
The adapter does not expose deterministic key generation or configure a test RNG.

## Installation tests

Run the ordinary suite without PQ installed. Native tests are explicitly opt-in:

```sh
STROMA_TEST_LIBOQS=/absolute/path/to/liboqs.dylib \
  python -m pytest tests/test_pq_backend.py
```

Native tests check public disposable fixtures, fresh key generation, signature
and context tampering, and KEM implicit rejection. They use no wallet keys,
relays or network services. The initial native build was tested on macOS arm64;
other platforms still need qualification. Independent cryptographic review and
full HPKE interoperability remain release gates.
