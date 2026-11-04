# Project Status

## Pre-release

Stroma is an early, independently installable protocol component. It is not yet
the active Nostr implementation inside Safebox Acorn.

## Implemented

- key generation and NIP-19 key conversion;
- [secp256k1 curve primitives](curve-primitives.md) for protocol-neutral point arithmetic;
- canonical NIP-01 events and BIP-340 signatures;
- NIP-19 TLV entities;
- NIP-44 version 2 and extended-length prefixes;
- NIP-59 wrapping with explicit timestamp and rumour-kind policies;
- NIP-40 expiration tags;
- relay publish acknowledgements and EOSE queries;
- relay-pool quorum and deduplication behavior;
- stable protocol error types.
- optional `pq` packaging and the experimental `stroma.pq.PQBackend` adapter;
- ML-DSA-44 key generation, signing and verification with explicit context;
- ML-KEM-768 key generation, encapsulation and decapsulation;
- explicit native-library loading with version checks and no runtime installer.

## Verified

- official NIP-44 example vector;
- official 65,535, 65,536, and 65,537-byte payload hashes;
- two-way NIP-44 compatibility with Acorn's current dependency below its
  legacy length limit;
- signed-event validation and tamper rejection;
- curve generator vectors, invalid scalars/points, and infinity rejection;
- Clear migration regression coverage for unchanged keyset identity and signature output;
- NIP-59 round trips and wrong-recipient rejection;
- local WebSocket relay publishing and querying;
- package metadata, source distribution, and wheel builds.
- installation with and without PQ dependencies;
- PQ fixtures, tamper/context rejection and native primitive round trips;
- application interoperability: pqrelay published and retrieved classical and
  ML-DSA-44 events between a development machine and a Docker relay on Beelink
  (user-reported successful end-to-end test).

## PQ scope and remaining work

The optional backend is implemented; the proposed signed/encrypted envelope,
full HPKE interoperability, application key recovery and identity trust are not
provided by it. Native qualification so far covers local macOS testing and the
reported Linux Docker deployment, not every supported Python/OS combination.
Independent cryptographic review remains required before production use.

See [installation and API](post-quantum-backend.md) and the
[envelope design and remaining gates](post-quantum-design.md).

## Next

1. Add captured Acorn event interoperability fixtures.
2. Add live third-party relay tests without making them part of the default
   unit suite.
3. Harden malformed relay-frame and timeout behavior.
4. Introduce Stroma into Acorn behind a migration adapter.
5. Complete the Acorn live-test gate before removing `monstr`.
