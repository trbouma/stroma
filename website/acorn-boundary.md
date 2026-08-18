# Stroma and Acorn

## Summary

Stroma is the Nostr wire-format layer beneath Acorn. Acorn remains responsible
for keys, funds, records, recovery, continuity, and the meaning of its event
kinds.

```text
Acorn says:  "This kind 7375 event represents wallet proof state."
Stroma says: "This event is correctly encoded, signed, encrypted, and exchanged."
```

## Why separate the components

Acorn previously inherited a broad Nostr dependency and then added local
changes for NIP-44 payload handling, NIP-59 timestamps, gift-wrap kinds,
expiration, and relay behavior. Stroma turns that accumulated protocol
experience into a narrow, independently tested boundary.

This creates three benefits:

1. Acorn can evolve its wallet and record model without changing the transport
   implementation.
2. Nostr protocol behavior can be tested against published vectors without
   constructing a wallet.
3. Other Safebox-family components can use the same wire mechanics without
   importing Acorn semantics.

## Migration approach

Migration will be incremental:

1. establish interoperability fixtures;
2. migrate NIP-44 storage encryption;
3. migrate NIP-59 gift wrapping;
4. migrate events, keys, signers, and NIP-19;
5. migrate relay operations in small groups;
6. run the complete Acorn unit and live relay-suitability suites;
7. remove the old dependency only when no compatibility paths remain.

Relay behavior is the highest-risk part of the migration because it affects
timeouts, acknowledgements, read-after-write checks, EOSE processing, and
async cleanup.

[Read the detailed migration plan](https://github.com/trbouma/stroma/blob/main/docs/ACORN-MIGRATION.md){ .md-button }
