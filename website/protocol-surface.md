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
| NIP-59 | Rumour, seal, and ephemeral gift-wrap construction and validation with zero timestamp jitter |
| NIP-40 | Optional expiration metadata on gift wraps |
| Relay operations | Publish acknowledgements, queries, EOSE, timeouts, and pooling |
| Blossom pool | Digest-verified retrieval and multi-server upload confirmation |

## Explicitly excluded

- social feeds, follows, reactions, and recommendation logic;
- relay-server implementation or relay persistence;
- wallet, mint, proof, balance, or payment semantics;
- private-record schemas or application indexes;
- Blossom server operation, retention, payment, and attachment policies;
- OpenETR control semantics;
- NIP-05 domain policy;
- local application state;
- novel cryptographic primitives.

## Payload limits

`BlossomPool` retrieves the first SHA-256-verified copy from configured servers
and optional hints. It also stores exact bytes on multiple targets, defaulting
to `require="any"`. Other requirements are `half` (ceil(N/2)), `majority`
(floor(N/2)+1), and `all` (N), calculated over unique target origins including
unavailable servers. Empty pools are rejected.

Storage attempts all targets and returns per-server outcomes and an `ok`
property. Only verified read-back counts as confirmation; a timeout may leave
an unconfirmed upload that actually succeeded. Confirmation is not consensus or
permanent retention. Applications own the choice of servers and how confirmed
locations are represented in records.

Operations have bounded concurrency, time, and size. Public HTTPS destinations
are required by default; redirects are disabled. Private networking and plain
HTTP require explicit operator opt-in for local development. See the
[Blossom API and limits](https://github.com/trbouma/stroma#blossom-pool) for
examples, supported protocol operations, and security constraints.

The current NIP-44 protocol supports an extended prefix above 65,535 bytes.
Stroma implements that format but defaults to a 262,143-byte plaintext ceiling
to bound memory use. Applications should still keep relay events modest and
place large attachments in a purpose-built blob protocol.

## Error boundary

Stroma exposes stable error categories for malformed keys, invalid events,
failed encryption, invalid gift wraps, relay failures, and explicit relay
rejections. Applications can respond to those categories without parsing
library log messages.
