# Stroma Component Boundary

## Purpose

Stroma is a minimal interface to Nostr as a wire format. It provides the
protocol mechanics needed to exchange opaque application payloads through
relays without taking ownership of application meaning or state.

The governing rule is:

> Stroma knows how an event is encoded, protected, published, queried, and
> verified. It does not know what the event means.

## Stroma owns

- protocol-neutral secp256k1 point arithmetic through `CurvePoint`;
- Nostr key representation required by wire protocols;
- canonical NIP-01 event serialization;
- BIP-340 event signing and verification;
- NIP-19 wire identifiers;
- NIP-44 encryption and authenticated decryption;
- NIP-59 envelope construction and inspection;
- NIP-40 expiration metadata on envelopes;
- filters, relay messages, publication acknowledgements, and EOSE handling;
- bounded async connection cleanup;
- Blossom byte retrieval, SHA-256 verification, upload authorization, and replication outcomes;
- stable protocol-specific errors.

## Stroma does not own

- Acorn configuration or wallet state;
- Cashu proofs, mints, balances, or payments;
- record schemas, control history, or OpenETR semantics;
- Blossom server implementation, retention guarantees, or application attachment policies;
- NIP-05 domain trust;
- relay persistence or a relay-server implementation;
- user interfaces, sessions, databases, or service workers;
- post-quantum trust policy, private-key persistence or recovery.

The optional [PQ backend](../website/post-quantum-backend.md) provides experimental
ML-DSA-44 and ML-KEM-768 primitives. Opaque envelopes remain a design proposal.
Neither layer owns application key-management policy or changes standard Nostr events.

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

## Shared curve primitives

`stroma.CurvePoint` exposes SEC1 parsing/serialization, generator multiplication,
point multiplication, and addition through coincurve. `stroma.CURVE_ORDER`
provides the scalar order. Scalars must be exactly 32 bytes and in `[1, n-1]`;
invalid points and results at infinity raise `ValueError`. Operations return new
points and retain no private scalar. Both compressed and uncompressed SEC1
encodings are accepted; x-only Nostr keys are a separate API.

Clear can use these primitives without importing coincurve directly. Cashu
hash-to-curve, blinding, keyset derivation, proof verification, and treasury
policy remain in Clear. This does not add Cashu protocol semantics to Stroma.


Additive key tweaking is also protocol-neutral: `Keys.tweak_add()` returns a new
keypair, and `CurvePoint.tweak_add()` returns its publicly derivable point.
The digest is caller-supplied, exactly 32 bytes and below the curve order;
zero tweaks are allowed, zero derived secrets/infinity are rejected.
Explicit x-only mode normalizes the parent to even Y, preserving output parity.
`CurvePoint.from_xonly()` lifts a 32-byte public key to even Y. Applications own
hash domain separation and key-derivation policy; these are not Cashu or Taproot
protocol implementations. See the [API examples](../website/curve-primitives.md).
