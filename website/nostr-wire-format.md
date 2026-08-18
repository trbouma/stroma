# Nostr as a Wire Format

## Summary

Stroma treats Nostr as a compact wire format for signed, encrypted,
relay-backed events. Social media is one use of Nostr, not a boundary on what
the protocol can carry.

At its simplest, a Nostr event supplies:

```text
author key + timestamp + kind + tags + content + signature
```

That is enough for applications to exchange opaque, verifiable objects without
agreeing on a central database or application provider.

## What this enables

### Portable authority

An event signature can be validated independently of the application that
created or displayed it. The key establishes cryptographic authority; the
application decides what that authority means in context.

### Typed application messages

An integer kind and a set of tags let an application define its own protocol
messages while retaining the same event envelope and relay transport.

### Encrypted payloads

NIP-44 provides authenticated encryption between keys. NIP-59 can place an
encrypted event inside a separately signed seal and ephemeral outer envelope,
reducing visible sender-recipient correlation.

### Replaceable transport

Events can be published to or queried from different compatible relays. A
relay stores and transports events; it does not have to understand Acorn's
wallet or record semantics.

## Wire format, not system of record

Stroma does not decide which event is authoritative application state. Acorn
may apply canonical-record, continuity, replication, or recovery rules over
the events it retrieves. Stroma provides the verified inputs to those rules.

This distinction keeps the protocol layer useful without turning it into an
application framework.
