# Optional Post Quantum Cryptography Design

Status: experimental primitives implemented, 2026-10-31. The optional
[backend and installation extra](post-quantum-backend.md) are available; the
envelope format below remains a proposal, not an implemented or finalized protocol.

Stroma should offer optional ML-DSA signatures and ML-KEM key establishment for
opaque application payloads while preserving its existing Nostr wire behavior.
Acorn and other callers remain responsible for identity trust, key persistence,
recovery, authorization and application state.

## Scope and compatibility

ML-DSA signs data; it does not encrypt it. ML-KEM establishes a shared secret;
it does not by itself encrypt an arbitrary record or authenticate its sender.
These roles are specified by [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final)
and [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), respectively.

The initial design targets signed payloads and authenticated encrypted envelopes
carried inside ordinary Nostr event content or stored as opaque Blossom bytes.
Existing `Keys`, `Event`, `Signer`, NIP-19, NIP-44 and NIP-59 behavior stays unchanged.
Do not place PQ keys in `npub`/`nsec` encodings or reinterpret NIP-44 version 2.

Standard outer events keep NIP-01's classical public key and signature format.
The inner envelope supplies additional PQ protection verified by the application.
This preserves relay transport compatibility, subject to payload-size limits,
but does not upgrade relay authentication, deletion, replacement or availability
to post-quantum security. Native PQ events requiring modified relays are a separate
experimental protocol, not an implicit change to Stroma. See
[NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md).

## Selected cryptographic suite

The design fixes the following algorithms; they are no longer candidates:

| Function | Selected algorithm |
| --- | --- |
| Payload signatures | ML-DSA-44 |
| Shared-secret establishment | ML-KEM-768 |
| Key derivation | HKDF-SHA-256 |
| Authenticated payload encryption | AES-256-GCM |

Only these choices are supported by the proposed PQ component. There is no
algorithm or parameter-set negotiation and no silent fallback. Version and suite
identifiers remain explicit so a decoder can reject unsupported formats, not
select an alternative algorithm. Existing classical Nostr operations remain
separate and unchanged. Classical-plus-PQ hybrid constructions are out of scope.

HKDF-SHA-256 derives the encryption key from the ML-KEM-768 shared secret using
explicit domain separation and envelope context. AES-256-GCM uses a 32-byte key,
a 12-byte nonce and a full 16-byte authentication tag in this proposed profile.
Nonce reuse under the same key is prohibited. Authentication must succeed before
plaintext is released. The envelope section below selects the construction and
encoding; independent test vectors and cryptographic review remain required.

Choosing these primitives alone does not establish security or HPKE conformance.
The selected experimental construction below references
[HKDF RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html),
[HPKE RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html) and
[NIST GCM SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)
as construction references during the remaining protocol review.

## Threat model

| Threat | Intended protection | Boundary or residual risk |
| --- | --- | --- |
| Recorded ciphertext attacked by future quantum computation | ML-KEM-based envelope encryption with independently protected secrets | Classical-only wrapping of PQ private keys can defeat this protection |
| Modification or forgery of protected payloads | ML-DSA verification against an authenticated expected key | A signature under an attacker-supplied key is not identity authentication |
| Algorithm substitution or downgrade | Bind version, suite and purpose; enforce caller's required policy | No silent fallback on failure or missing capability |
| Recipient or context substitution | Authenticate recipient key identity and application context | Application must supply and check the expected context |
| Replay or rollback of valid data | Bind message identity and revision context | Application maintains freshness/continuity state; Stroma cannot infer the latest record |
| Malicious relay or blob host | Verify envelope and content integrity independently of transport | Hosts can censor, withhold, replay or correlate traffic |
| Oversized or malformed inputs | Bounded parsing, exact algorithm lengths and controlled work | Resource ceilings must be specified and tested |
| Compromised endpoint or crypto provider | Outside the protection of envelope cryptography | Plaintext and active private keys may be exposed |

No claim is made of forward secrecy from a static recipient KEM key. Compromising
that key can expose recorded envelopes addressed to it. Outer routing metadata,
traffic patterns and visible header fields are not confidential. Re-encrypting
old data does not erase copies already harvested under weaker protection.
FIPS algorithm use is not equivalent to FIPS validation of a cryptographic module.

## Component boundary and optional provider

The implemented module is `stroma.pq`, exposing `PQBackend`, `PQKeyPair`,
`PQBackendUnavailable` and `PQOperationError`. It provides fixed-suite primitive
operations; the nested signatures/kem/envelopes module layout originally proposed
here is not an importable API. Envelope encoding and binding remain future work.

The `stroma-nostr[pq]` extra installs the pinned optional Python dependency.
Native liboqs is provisioned separately, including explicit Docker build-time
compilation where appropriate. Ordinary imports do not load liboqs, download code
or invoke native builds. Missing or incompatible support raises
`PQBackendUnavailable` when the backend is constructed.
Malformed data, unsupported suites and invalid authentication must be distinguishable
for local diagnostics without exposing secret-dependent detail to remote callers.

Use a maintained cryptographic provider, not a new implementation of the algorithms.
Pin and test compatible Python/native-library versions. Production installation
must provision dependencies ahead of runtime and fail closed if unavailable.
The [liboqs-python documentation](https://github.com/open-quantum-safe/liboqs-python/blob/main/README.md)
describes automatic native-library installation; that convenience must not become
an uncontrolled Stroma import side effect. Backend choice and production suitability
remain subject to review. Bound concurrency and avoid blocking async relay processing
with unbounded cryptographic work.

## Key lifecycle

1. **Generate:** use provider-supported secure randomness. Signing and KEM keys
   are separate types and purposes. Use only ML-DSA-44 for signatures and
   ML-KEM-768 for key establishment. Do not infer algorithms from key length.
2. **Identify:** use the canonical descriptors and domain-separated SHA-256
   identifiers specified below. Identifiers are lookup handles, not trust anchors;
   callers authenticate the complete public descriptor.
3. **Establish trust:** the caller supplies an authenticated expected descriptor or
   an accepted trust chain. Classical Nostr signatures can assist initial migration,
   but do not alone provide durable PQ identity assurance after classical compromise.
   Pinning must follow a trustworthy bootstrap; self-signing a new key is insufficient.
4. **Store and recover:** caller-owned protected storage or a key service retains
   private keys. Stroma neither chooses relay records nor stores wallet recovery data.
   Backups must protect PQ secrets independently of a quantum-vulnerable credential
   when that is part of the claimed threat model.
5. **Rotate:** bind old/new identities, algorithm, epoch and intended purpose in an
   authenticated transition. Callers enforce monotonic state and reject rollback.
   Compromise recovery needs an independent authority or recovery mechanism; an
   already compromised key cannot establish trustworthy continuity by itself.
6. **Retire:** distinguish signing retirement from decryption-key retention needed
   for archives. Record retention, revocation and historical-signature acceptance
   are application policy. A signature timestamp alone is not trusted proof that
   signing preceded compromise.

For Acorn specifically, deriving PQ private keys solely from an nsec, or encrypting
them solely under an nsec-derived key, does not provide independence from compromise
of that nsec. This conflicts with assuming nsec-only recovery is sufficient for
full PQ resilience. Acorn must explicitly choose a separate high-entropy recovery
secret, protected key service or another reviewed design. No deterministic derivation
or mnemonic scheme is specified here. Never log private material; minimize copies
and lifetime without promising guaranteed erasure in Python.

## Proposed envelope contract

The following selects experimental profile `stroma-pq-v1`. It supports one signed
and encrypted message for one recipient. Signed-only envelopes, multiple recipients,
streaming, compression and large-blob chunking are deferred. Low-level signature
primitives may still be exposed independently. No production compatibility promise
is made before independent review and interoperable fixtures.

| Field | Required binding |
| --- | --- |
| `version`, `profile`, `suite` | Exact protocol and cryptographic interpretation |
| `purpose` | Domain such as private record or authorization; caller checks expected purpose |
| `sender_key_id` | Expected signing descriptor; embedded public keys alone do not establish trust |
| `recipient_key_id` | Intended KEM descriptor for encrypted profiles |
| `message_id`, `context` | Stable message identity and opaque caller-supplied record/revision/audience context |
| `kem_ciphertext` | Encapsulation output, authenticated with the envelope header |
| Derived nonce | HPKE sequence-zero nonce; not transmitted or caller-supplied |
| `body` | Canonical signed payload or authenticated ciphertext, according to profile |
| `signature` | ML-DSA authentication of the explicitly defined signed transcript |

### Encoding and key descriptors

Let `C(x)` mean the core deterministic CBOR encoding in
[RFC 8949 section 4.2.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1).
This profile uses fixed-position arrays, unsigned integers, byte strings and
restricted ASCII text only. Require definite lengths and shortest encodings;
reject maps, tags, floats, nulls, indefinite lengths, trailing bytes and extra
array elements. Opaque payload/context byte strings are not recursively decoded.
Quoted strings below are CBOR text strings, not byte strings.

Public descriptors are exactly:

```text
DS = C([1, "sign", "ML-DSA-44", signing_public_bytes])
DK = C([1, "kem", "ML-KEM-768", recipient_public_bytes])
kid(D) = SHA-256(C(["stroma-pq-key-v1", D]))
```

`D` in `kid(D)` is a byte string containing the canonical descriptor. Public key
bytes use the respective FIPS encoding and exact lengths. Private keys are not
part of the envelope and have no Stroma wire serialization in v1. Resolve both
descriptors through caller-supplied trusted material; never fetch arbitrary URLs
or trust an embedded public key based solely on its matching identifier.

### Exact header and signing input

The canonical header bytes are:

```text
H = C([1, 1, 1, purpose, sender_kid, recipient_kid, message_id, context])
T = C(["stroma-pq-sign-v1", H, payload])
P = C([payload, signature])
```

The first three integers identify version, signed/encrypted profile and the
fixed suite respectively; only value 1 is accepted for each. Key IDs are 32-byte
strings. `message_id` is 16 freshly random bytes. `purpose` is 1–64 ASCII characters
from `[a-z0-9._/-]`; `context` is 0–4096 opaque bytes, and `payload` is 0–1,048,576
opaque bytes. The caller supplies expected purpose and exact context when opening
an envelope; these may bind recipient audience, record version or order identity.

Sign `T` with ordinary FIPS 204 ML-DSA-44 using context bytes
`ASCII("stroma-pq-v1")` and the randomized signing variant. Do not prehash `T`
outside ML-DSA or substitute HashML-DSA. `signature` is the resulting raw signature
byte string; verify its exact FIPS length. If a backend cannot honor this signing
context, fail capability checks rather than changing the signed transcript.

### Encryption construction and nonce ownership

Use RFC 9180 HPKE base mode with KEM `0x0041` (ML-KEM-768), KDF `0x0001`
(HKDF-SHA-256) and AEAD `0x0002` (AES-256-GCM). Pin the ML-KEM KEM mapping to
[draft-ietf-hpke-pq-05 section 3](https://www.ietf.org/archive/id/draft-ietf-hpke-pq-05.html#section-3),
an Internet-Draft, not a final standard. Use random key generation; deterministic
HPKE `DeriveKeyPair` is not exposed. Seed versus expanded private-key representation
is a backend-adapter concern and must not change public bytes or encapsulation.

Use RFC 9180 sections 5.1 and 5.2 without modifying the labeled extract/expand
schedule. PSK and PSK ID are empty. HPKE owns salt handling and the derived nonce;
there is no application salt or nonce field. The selected suite is pure ML-KEM,
not a classical/PQ hybrid; HPKE's name does not imply adding a classical KEM.

The Stroma-specific inputs and output are:

```text
info = C(["stroma-pq-hpke-v1", H])
(enc, sender_context) = SetupBaseS(recipient_public_key, info)
aad = C(["stroma-pq-aad-v1", H, enc])
ct = sender_context.Seal(aad, P)
envelope = C([H, enc, ct])
```

Every envelope uses fresh encapsulation randomness and a new HPKE context for
exactly one sequence-zero Seal. Destroy/discard the context after use; never
reuse it to edit a message, retry encryption or send another payload. A delivery
retry retransmits identical envelope bytes. A newly constructed message needs
fresh randomness and identity. Do not expose raw nonce/key overrides outside
isolated test-vector tooling. Failure of randomness generation is fatal.

The header is visible, including sender/recipient key IDs and context. Keep private
record labels and personal data in the encrypted payload; opaque IDs still permit
correlation. The signature is encrypted. This application envelope is not a claim
that arbitrary HPKE implementations understand Stroma's framing. Draft changes
require explicit profile/version review, never silently changed cryptographic inputs.

### Receiver validation order and limits

1. Bound input before parsing: maximum binary envelope 1,064,960 bytes (1 MiB plus
   16 KiB). Parse a three-element array and canonical header with the exact types
   and limits above. Reject unsupported constants, noncanonical/trailing bytes and
   invalid key IDs. Verify `enc` is exactly 1088 bytes; ciphertext includes a full
   16-byte GCM tag. Never accept a truncated tag.
2. Resolve trusted descriptors and validate exact algorithm/public-key lengths.
   Match recipient key, expected sender, purpose and context. Unauthenticated
   headers can be used for rejection, never authorization or replay-state updates.
3. Recreate `info` and `aad`, call `SetupBaseR(enc, recipient_private_key, info)`,
   and Open once at sequence zero. Implicit KEM rejection does not establish
   validity; GCM authentication must succeed. Buffer decrypted bytes internally.
4. Parse canonical `P` as exactly two byte strings, enforce payload/signature limits,
   reconstruct `T` and verify ML-DSA with the specified context and trusted sender.
   Release no plaintext until every check succeeds; HPKE base mode alone does not
   authenticate the sender.
5. Return authenticated metadata and payload. Caller atomically applies replay and
   revision policy before acting. The replay identity includes sender, recipient,
   purpose and message ID, not just ciphertext hash: re-encryption must not bypass it.

Decoder container nesting is limited to four; encoded byte strings remain opaque
until their explicitly defined parsing stage. Text transport, when required for
Nostr content, is exactly `stroma-pq-v1:` plus canonical unpadded base64url of the
envelope. Bound text to 1,419,960 ASCII characters before decoding and verify
re-encoding equality. No alternate alphabets, whitespace or padding are accepted.
Applications may impose lower ceilings; v1 cannot raise these limits. Relays may
reject messages below these ceilings, so clients must respect relay limits too.

Return a generic invalid-envelope error to remote consumers for parse, decryption
and signature failures, with redacted local diagnostics. Do not claim constant-time
end-to-end handling. Capability failures remain explicit locally. No retry loop or
classical fallback is triggered by opening failure. Async callers should run crypto
through a bounded executor (proposed default two active operations and queue of 16
per process); overflow fails explicitly rather than creating unbounded tasks.

## Transport and policy separation

Stroma accepts opaque context bytes; it does not interpret an OpenETR record, Cashu
token or payment approval. The caller checks that verified context matches the
requested operation and enforces replay protection. Parse/verify results should
report the actual profile and suite, not a universal `quantum_safe` boolean.

Persisted minimum-security policy and authenticated capability/key discovery belong
to the caller. An attacker removing a PQ envelope must not make a PQ-required caller
accept a classical substitute. Explicit legacy operation can remain supported,
but it must be visibly distinct from the PQ path and never a retry after PQ failure.

PQ payload integrity does not stop a compromised classical identity from replacing
or deleting relay-visible events. Applications need independent continuity state,
replication and authenticated recovery if that risk is in scope. Blossom digest
verification establishes byte integrity, not authorship, confidentiality or retention.

## Lessons from pqrelay

The sibling prototype demonstrates modified-relay signature transport. Before
reuse, replace implicit length-based dispatch with typed descriptors; align its
Falcon-512 implementation with its ML-DSA documentation; recompute canonical event
IDs before signature verification; and replace floating dependencies with controlled
builds. ML-KEM is new work, not a feature established by that signature experiment.

The priority here is optional payload protection over existing relays. A native
PQ event protocol can remain a separate experiment with its own relay capability
negotiation, filtering, identity and storage semantics.

## Decisions and validation before implementation

### Safebox 2 integration lessons

The legacy Safebox 2 record flow provides an application-level precedent beyond
pqrelay: service-generated independent KEM keys, recipient discovery through
`/.well-known/kem`, encapsulation for record delivery and AES-256-GCM protection
of transferred attachments. Carry forward those requirements, not its wire format.

Its default ML-KEM-512, temporary secp256k1/NIP-44 wrapping and direct use of a KEM
secret as a blob key are not compatible with this fixed ML-KEM-768 HPKE profile.
Any legacy decryption/migration must be explicit application code, never automatic
fallback inside Stroma. The inspected transfer path did not use the legacy
`PQEvent` ML-DSA class to sign its inner record; the new profile requires that signature.

Do not reproduce legacy paths that print shared secrets/plaintext or continue
record ingestion after PQ decryption fails. Stroma returns no usable plaintext on
failure. Its callers must not turn invalid protected messages into accepted records.
An independently protected service KEM key can protect an incoming transfer, but
accepted records subsequently stored under an nsec-only scheme have a separate
at-rest threat model. Loss of the service KEM key also affects unaccepted transfers;
wallet nsec recovery does not automatically recover them.

### Offline fixture progress

The [test harness and reproducibility instructions](https://github.com/trbouma/stroma/tree/main/tests/pq_vectors)
provide two disposable vectors with canonical transcripts, ML-DSA signatures,
ML-KEM encapsulations, HPKE intermediates and AES-GCM ciphertexts. Test tooling
is outside the distributed `stroma` package and introduces no production dependency.
liboqs generation was checked with OpenSSL's independent default-provider signature
and KEM implementations and a second AEAD backend. This is primitive-level evidence,
not independent validation of a complete HPKE or Stroma envelope implementation.

An isolated `liboqs-python` compatibility probe also passes the fixtures and fresh
signature/KEM round trips with wrapper commit
`d552e3a55985e5a2396545d744be0a01321ddbc3` and native liboqs 0.14.0.
This historical pin is test evidence, not production approval. The wrapper attempts
automatic native installation when loading fails; the probe bypasses that path and
blocks network/process execution. The experimental adapter now uses maintained
release pins and a narrow direct C binding instead of importing the installer.
Independent review remains required before production use. Ordinary
Stroma imports must remain independent of the optional backend. See the harness
README for reproduction and the limits of the test-only loader injection.

### Remaining gates

The encoding, single-message construction and validation policy above are selected
design decisions. Resolve these remaining gates before production implementation:

- Confirm the threat profile; provider/platform support for the fixed suite and release pins.
- Independent review of the selected transcripts, pinned HPKE draft mapping and
  implementation support for ML-DSA context bytes.
- Trust bootstrap, key discovery, rotation/revocation and independent recovery policy.
- Benchmark the specified byte/concurrency limits and validate bounded async integration.
- Single-recipient signed/encrypted interoperability fixtures and separate large-blob scope.

Required tests include standards/provider vectors and cross-implementation fixtures;
wrong keys, altered payload/header/context, stale revisions, stripped PQ protection,
invalid encapsulations and authentication tags; malformed/oversized encodings;
missing backend and unsupported algorithms; rotation/recovery and key substitution;
and unchanged classical Stroma behavior without PQ dependencies. Benchmarks should
measure encoded sizes, latency, memory and concurrent load, not just crypto time.

Continue the offline fixtures with an independent HPKE/envelope implementation and
the remaining negative cases. Deterministic randomness is allowed only in the
isolated test harness, never through production APIs. Do not contact live relays, migrate wallet
keys or encrypt production records as part of the design step. Neither this proposal
nor passing tests is a substitute for independent cryptographic review.
