---
title: Stroma
description: A minimal Python interface to Nostr as a signed, encrypted, relay-backed wire format.
---

<section class="stroma-hero" markdown>

# Stroma

<img class="stroma-hero-mark" src="assets/images/stroma-logo.png" alt="Stroma logo showing the layered structure of a stromatolite fossil with purple protocol channels">

<p class="stroma-tagline">Nostr as a signed, encrypted, relay-backed wire format.</p>

<p class="stroma-intro">A compact Python protocol layer for Safebox Acorn and other applications that need events, encryption, gift wrapping, and reliable relay exchange—without importing an entire social client.</p>

[Understand Stroma](nostr-wire-format.md){ .md-button .md-button--primary }
[View the source](https://github.com/trbouma/stroma){ .md-button }

</section>

## A narrow protocol layer

Stroma exists to give Acorn a deliberate interface to Nostr. It handles the
wire mechanics while leaving application meaning where it belongs.

<div class="stroma-grid" markdown>

<article class="stroma-card" markdown>

### Signed events

Canonical NIP-01 serialization, secp256k1 keys, BIP-340 signatures, event
validation, tags, and NIP-19 identifiers form a small interoperable base.

</article>

<article class="stroma-card" markdown>

### Protected payloads

NIP-44 authenticated encryption protects opaque application payloads. Stroma
implements the current extended-length format and applies an explicit resource
ceiling suitable for Acorn.

</article>

<article class="stroma-card" markdown>

### Relay exchange

Bounded publish and query operations make acknowledgements, EOSE completion,
timeouts, deduplication, and connection cleanup visible rather than implicit.

</article>

</div>

## Structure beneath the surface

Stromatolites preserve layer upon layer of structure. Stroma takes inspiration
from that pattern: a thin, dependable protocol layer beneath applications,
with each responsibility kept visible and testable.

```text
Safebox Web and other applications
                 |
               Acorn
                 |
              Stroma
                 |
       Nostr events and relays
```

**Stroma knows how an event is encoded, protected, published, queried, and
verified. It does not know what the event means.**

[Explore the protocol boundary](protocol-surface.md){ .md-button .md-button--primary }
[See how Acorn will use Stroma](acorn-boundary.md){ .md-button }

## Deliberately not a social client

Nostr is often presented through social applications, but its underlying
format is more general: signed events, typed payloads, tagged relationships,
and replaceable relay infrastructure. Stroma exposes that smaller substrate.

It does not implement feeds, follows, reactions, profiles, wallet state,
Cashu, records, Blossom, OpenETR, or a relay server. Those capabilities can use
Stroma without becoming part of Stroma.

## Project status

Stroma is pre-release software. Its first protocol slice passes official
NIP-44 vectors, extended-length boundary tests, key and event tests, NIP-59
round trips, and an in-process relay exchange test. Safebox Acorn still uses
its existing Nostr dependency while migration fixtures and live tests are
developed.

[Review project status](project-status.md){ .md-button }
[Read the security statement](security.md){ .md-button }
