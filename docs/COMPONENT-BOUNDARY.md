# Stroma Component Boundary

## Purpose

Stroma is a minimal interface to Nostr as a wire format. It provides the
protocol mechanics needed to exchange opaque application payloads through
relays without taking ownership of application meaning or state.

The governing rule is:

> Stroma knows how an event is encoded, protected, published, queried, and
> verified. It does not know what the event means.

## Stroma owns

- Nostr key representation required by wire protocols;
- canonical NIP-01 event serialization;
- BIP-340 event signing and verification;
- NIP-19 wire identifiers;
- NIP-44 encryption and authenticated decryption;
- NIP-59 envelope construction and inspection;
- NIP-40 expiration metadata on envelopes;
- filters, relay messages, publication acknowledgements, and EOSE handling;
- bounded async connection cleanup;
- stable protocol-specific errors.

## Stroma does not own

- Acorn configuration or wallet state;
- Cashu proofs, mints, balances, or payments;
- record schemas, control history, or OpenETR semantics;
- Blossom objects or application attachment policies;
- NIP-05 domain trust;
- relay persistence or a relay-server implementation;
- user interfaces, sessions, databases, or service workers;
- post-quantum policy or algorithms.

## Dependency direction

```text
Safebox Web and other applications
              |
            Acorn
              |
           Stroma
              |
  established crypto + WebSocket transport
```

Stroma must never import Acorn. Event kinds and payload schemas belonging to
Acorn are passed to Stroma as opaque integers, tags, and strings.

## Compatibility policy

Stroma may preserve a small number of familiar names such as `Keys`, `Event`,
`Entities`, `NIP44Encrypt`, and `BasicKeySigner` to reduce migration risk. This
does not make it a drop-in replacement for the complete `monstr` package.

Compatibility is evaluated against behavior used by Acorn, not against every
historical `monstr` feature.
