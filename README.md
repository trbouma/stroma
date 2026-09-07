# Stroma

Stroma is Safebox's minimal Python interface to Nostr as a signed, encrypted,
relay-backed wire format.

It knows how an event is encoded, signed, encrypted, wrapped, published,
queried, and verified. It does not know what the event means. Wallets, funds,
records, application schemas, and business rules remain outside Stroma.

> The project is branded **Stroma**. The Python distribution is named
> `stroma-nostr` because the `stroma` distribution name is already occupied on
> PyPI. The import package is `stroma`.

## Initial scope

- secp256k1 keypairs and NIP-19 key encoding;
- NIP-01 event serialization, BIP-340 signing, and validation;
- NIP-19 profile, event, relay, and address entities;
- deterministic FIPS IPv6 address derivation from Nostr public keys;
- NIP-44 version 2 encryption, including its extended length prefix;
- NIP-59 gift wrapping with an explicit timestamp policy;
- NIP-40 expiration tags on gift wraps;
- operation-scoped relay publishing, acknowledgement, and querying;
- relay-pool quorum publishing and deduplicated querying.

Stroma deliberately excludes social-client behavior, a relay server, Cashu,
Blossom, OpenETR, application records, wallet state, and local persistence.

## Install for development

```console
poetry install
poetry run pytest
```

Until Stroma is published, another local project can use it with:

```console
pip install -e /Users/trbouma/projects/stroma
```

## Small example

```python
from stroma import Event, Keys, NIP44Encrypt

alice = Keys()
bob = Keys()

event = Event(kind=1, content="hello", pub_key=alice.public_key_hex())
event.sign(alice)
assert event.is_valid()

payload = NIP44Encrypt(alice).encrypt("private", bob.public_key_hex())
assert NIP44Encrypt(bob).decrypt(payload, alice.public_key_hex()) == "private"
```

FIPS-compatible IPv6 addresses are derived without network access:

```python
from stroma import fips_ipv6_address

address = fips_ipv6_address(alice.public_key_bech32())
```

## Project status

Stroma is pre-release. Safebox Acorn still uses `monstr`; migration will be
incremental and gated by compatibility tests and Acorn's complete live test
suite. See [the component boundary](docs/COMPONENT-BOUNDARY.md) and
[the Acorn migration plan](docs/ACORN-MIGRATION.md).

## Security

Stroma does not design new cryptographic algorithms. It implements published
Nostr formats using established cryptographic libraries and tests protocol
boundaries against published vectors. See [SECURITY.md](SECURITY.md).
