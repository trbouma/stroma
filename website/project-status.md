# Project Status

## Pre-release

Stroma is an early, independently installable protocol component. It is not yet
the active Nostr implementation inside Safebox Acorn.

## Implemented

- key generation and NIP-19 key conversion;
- canonical NIP-01 events and BIP-340 signatures;
- NIP-19 TLV entities;
- NIP-44 version 2 and extended-length prefixes;
- NIP-59 wrapping with explicit timestamp and rumour-kind policies;
- NIP-40 expiration tags;
- relay publish acknowledgements and EOSE queries;
- relay-pool quorum and deduplication behavior;
- stable protocol error types.

## Verified

- official NIP-44 example vector;
- official 65,535, 65,536, and 65,537-byte payload hashes;
- two-way NIP-44 compatibility with Acorn's current dependency below its
  legacy length limit;
- signed-event validation and tamper rejection;
- NIP-59 round trips and wrong-recipient rejection;
- local WebSocket relay publishing and querying;
- package metadata, source distribution, and wheel builds.

## Next

1. Add captured Acorn event interoperability fixtures.
2. Add live third-party relay tests without making them part of the default
   unit suite.
3. Harden malformed relay-frame and timeout behavior.
4. Introduce Stroma into Acorn behind a migration adapter.
5. Complete the Acorn live-test gate before removing `monstr`.
