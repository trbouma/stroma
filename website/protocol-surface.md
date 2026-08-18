# Protocol Surface

## Summary

Stroma implements the smallest coherent Nostr surface needed by Safebox Acorn.
Its API is intentionally narrower than a general-purpose Nostr client library.

## Included

| Surface | Responsibility |
| --- | --- |
| Keys | Generate and parse secp256k1 private and x-only public keys |
| NIP-01 | Serialize, identify, sign, validate, and inspect events |
| NIP-19 | Encode and decode keys, profiles, events, relays, and addresses |
| NIP-44 | Authenticated version 2 encryption and extended-length payloads |
| NIP-59 | Rumour, seal, and ephemeral gift-wrap construction and validation |
| NIP-40 | Optional expiration metadata on gift wraps |
| Relay operations | Publish acknowledgements, queries, EOSE, timeouts, and pooling |

## Explicitly excluded

- social feeds, follows, reactions, and recommendation logic;
- relay-server implementation or relay persistence;
- wallet, mint, proof, balance, or payment semantics;
- private-record schemas or application indexes;
- Blossom blob storage;
- OpenETR control semantics;
- NIP-05 domain policy;
- local application state;
- novel cryptographic primitives.

## Payload limits

The current NIP-44 protocol supports an extended prefix above 65,535 bytes.
Stroma implements that format but defaults to a 262,143-byte plaintext ceiling
to bound memory use. Applications should still keep relay events modest and
place large attachments in a purpose-built blob protocol.

## Error boundary

Stroma exposes stable error categories for malformed keys, invalid events,
failed encryption, invalid gift wraps, relay failures, and explicit relay
rejections. Applications can respond to those categories without parsing
library log messages.
