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
- NIP-59 gift wrapping with a fixed zero-jitter timestamp policy;
- NIP-40 expiration tags on gift wraps;
- operation-scoped relay publishing, acknowledgement, and querying;
- relay-pool quorum publishing and deduplicated querying.
- Blossom digest-verified retrieval and multi-server storage confirmation.

Stroma deliberately excludes social-client behavior, a relay server, Cashu,
OpenETR semantics, application records, wallet state, attachment/retention policy,
and local persistence. Blossom support is a client transport, not a storage server.

## Blossom Pool

```python
from stroma import BlossomPool, Keys

pool = BlossomPool(["https://blossom.example.org", "https://backup.example.org"])
stored = await pool.store(b"exact artifact bytes", signer=Keys())  # require="any"
if stored.ok:
    print(stored.digest, stored.confirmed_servers)
artifact = await pool.retrieve(stored.digest)
assert artifact.content == b"exact artifact bytes"
```

Production applications should pass their existing `Keys` or `Signer`, rather
than generate a fresh key for each upload. `store` attempts all unique targets;
`require` controls success, not the number of uploads attempted:

| Requirement | Confirmations for N unique targets |
| --- | --- |
| `any` (default) | 1 |
| `half` | `(N + 1) // 2` |
| `majority` | `N // 2 + 1` |
| `all` | N |

Unavailable targets remain in the denominator. Partial storage returns
a `BlossomStoreResult` whose `ok` property is false, with
`confirmed`, `rejected`, or `unconfirmed` per-server outcomes; it does not roll
back successful uploads. Confirmation requires a digest-verified GET, including
when the upload response was lost. The pool never explicitly retries an upload.
Confirmed availability is not a retention guarantee or consensus.

Retrieval races configured servers and optional `hints=[...]`, returns the first
SHA-256-verified copy, and cancels remaining work. `BlossomError.outcomes` gives
failures if no copy is verified. The result includes bytes, digest, server, and
declared media type; a media-type header is not proof that rendering is safe.
Origins are normalized and deduplicated across configured servers and hints
before applying `max_servers`. Hostname case, default ports, and a trailing slash
do not create separate targets. The first occurrence determines list order;
retrieval remains concurrent, not a sequence of fallback stages. Pass finite
candidate lists; applications remain responsible for bounding untrusted inputs.

Defaults: 10 seconds per HTTP request, 60 seconds per operation (including queue
and signer waits), four concurrent workers, 25 MiB per blob, and 32 unique server
origins. Servers must be HTTPS origins, with no credentials, path, query, or
fragment. DNS and literal destinations must be public. Redirects are not followed,
environment proxies and cookies are disabled, and TLS verification stays enabled.
`allow_private=True` and `allow_http=True` are explicit operator opt-ins for
local test deployments; never expose those switches to untrusted callers.
Applications must still decide which hints are permitted and apply egress controls.

The initial surface uses [BUD-01 retrieval](https://github.com/hzrd149/blossom/blob/master/buds/01.md),
[BUD-02 upload](https://github.com/hzrd149/blossom/blob/master/buds/02.md), and
[BUD-11 authorization](https://github.com/hzrd149/blossom/blob/master/buds/11.md).
Upload authorization is scoped to the digest and server domain. Authenticated
retrieval, redirects/CDN discovery, payment, mirroring, listing, deletion, and
retention management are not implemented. The pool does not create OpenETR
anchor events or choose event tags; an application can use `confirmed_servers`
when constructing its own location hints.

## Install for development

```console
poetry install
poetry run pytest
```

Until Stroma is published, another local project can use it with:

```console
pip install -e /Users/trbouma/projects/stroma
```

Applications should pin a tested tag or commit rather than use an editable
checkout in deployment. Update Stroma by changing the consuming application's
dependency pin and lock file, then run both Stroma's tests and the consuming
application's compatibility tests. Stroma is a library: it has no independent
service identity, persistent state, container, or refresh lifecycle.

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

Stroma is pre-release. Safebox Acorn's source and non-live tests now use
Stroma instead of `monstr`. Production use remains gated on a tested Stroma
commit pin, Acorn lock-file regeneration, and Acorn's configured live relay
suite. See [the component boundary](docs/COMPONENT-BOUNDARY.md) and
[the Acorn migration note](docs/ACORN-MIGRATION.md).

## Security

Stroma does not design new cryptographic algorithms. It implements published
Nostr formats using established cryptographic libraries and tests protocol
boundaries against published vectors. See [SECURITY.md](SECURITY.md).
