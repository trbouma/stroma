# Using Key Tweaks

Stroma's additive key tweaks let an application derive a context-specific
keypair while allowing another party to calculate its public key from the
parent public key and the same context. This is useful when a public,
verifiable relationship between keys is intentional.

The methods are implemented, but the application patterns below are
experimental examples, not standardized identity or authorization protocols.
A tweak creates a related key; it does not establish domain ownership,
delegation, compromise isolation, or post-quantum security.

## When this is useful

| Application pattern | What a tweak provides | What the application must supply |
| --- | --- | --- |
| Domain-specific signing identities | A repeatable key for a domain under one parent | Domain normalization, authenticated parent identity, and signing policy |
| Per-project or per-record keys | Distinct keys derived from stable context identifiers | Unambiguous identifiers and access controls |
| Public verification services | Expected child public keys without parent secrets | Trusted context and parent key, plus a decision about authorized uses |
| Versioned identities | Repeatable keys for an explicit version or epoch | Version discovery, revocation, and historical verification rules |

For example, a protected signer could derive a key for `example.com`, while a
verifier independently calculates its public key. The signer should keep both
parent and derived secrets inside its trusted boundary. Exporting a child
secret to a less-trusted application does not isolate that application from the
parent when the tweak is public.

## What the methods do

For a parent private scalar `d`, its public point `P = dG`, and a digest
interpreted as a big-endian integer `t`:

```text
child private key = (d + t) mod n
child public key  = P + tG
```

`n` is the secp256k1 curve order. `Keys.tweak_add()` returns another `Keys`
instance; `CurvePoint.tweak_add()` returns a new public point. Neither modifies
the original object. Stroma takes an already computed 32-byte `bytes` digest;
it does not hash the input again. Use SHA-256's `.digest()`, not `.hexdigest()`.

## Example: a domain-specific Nostr signing key

This example uses a fixed application prefix and an already canonical ASCII
DNS name. The prefix separates this purpose from unrelated uses of the same
parent key. It is an example encoding, not a Stroma wire standard.

```python
import hashlib
from stroma import CurvePoint, Event, Keys

# Fresh demonstration identity. In an application, securely load the same
# parent when you need to reproduce a derived key.
parent = Keys()
domain = "example.com"
context = b"example-app/domain-signing/v1:" + domain.encode("ascii")
digest = hashlib.sha256(context).digest()

child = parent.tweak_add(digest, x_only=True)
assert isinstance(child, Keys)
assert child.public_key_hex() == parent.tweak_add(
    digest, x_only=True
).public_key_hex()

event = Event(kind=1, content="A demonstration signed by the domain key")
event.sign(child)
assert event.is_valid()

# A verifier needs only the parent public key and the agreed context.
parent_public = CurvePoint.from_xonly(bytes.fromhex(parent.public_key_hex()))
expected_child = parent_public.tweak_add(digest)
assert expected_child.format()[1:].hex() == child.public_key_hex()
assert event.pub_key == expected_child.format()[1:].hex()
```

No event is published by this example. A real verifier must check both the
signature and the expected signer identity, and apply its own event-kind,
content, freshness, and authorization rules. A valid signature alone is not
proof that an action was permitted.

The domain text does not prove control of that domain. If that matters, bind
the parent or derived public key to separately authenticated domain evidence.
Anyone who knows the parent public key and context can calculate the expected
child public key, but they cannot thereby sign for it.

## Define the context before deploying

Both sides must hash exactly the same bytes. Record the following as part of
the application protocol:

- **Purpose and version:** use a fixed prefix, including an application and
  derivation version. Changing it changes the key.
- **Domain rules:** decide whether a key is per host or per registrable domain.
  Define lowercase handling, trailing-dot handling, and a specific IDNA profile
  if internationalized names are accepted. Do not silently equate `www.example.com`
  with `example.com`.
- **Input scope:** a DNS name is different from a URL or web origin. If scheme,
  port, tenant, role, or record ID matters, encode it explicitly.
- **Field encoding:** use an unambiguous, versioned encoding for multiple fields,
  such as specified length prefixes. Arbitrary concatenation is ambiguous.
- **Parent and mode:** record which parent identity and whether x-only
  normalization are used. Parent rotation changes derived identities.

Do not use Python's process-dependent `hash()` for persistent derivation.
Do not silently retry with different context bytes when an input is rejected.
A protocol that needs retries must specify an agreed counter encoding and make
that counter available to every verifier.

## Choose full-point or x-only mode

The default `x_only=False` uses the parent's actual point, including Y parity.
A public verifier needs the full SEC1 public point to reproduce that result.

For Nostr-style x-only identities, use `x_only=True`. Stroma first chooses the
even-Y parent point and, for an odd-Y parent, changes the private scalar to
`n - d` before adding the tweak. `CurvePoint.from_xonly()` chooses that same
even-Y point on the public side. This follows the even-Y convention described
in [BIP-340](https://bips.dev/340/).

The output keeps its actual parity. For a further x-only derivation step,
normalize again; do not assume the previous output already has even Y. Prefer
deriving sibling contexts directly from the parent unless an application
explicitly specifies a derivation hierarchy.

## Limits and failure handling

A tweak must be exactly 32 bytes, with integer value less than `CURVE_ORDER`.
Zero is permitted and leaves the selected parent point unchanged. The API
rejects out-of-range tweaks, zero derived private keys, and public results at
infinity with `ValueError`. It does not reduce the digest modulo the order.
Calling `Keys.tweak_add()` on a public-only `Keys` raises Stroma's `KeyError`.

Keep the method's rejection behavior intact. Do not replace failed derivations
with the parent key or a random key: that would break the identity agreement.
See [Curve Primitives](curve-primitives.md) for the complete API contract.

## Related keys are not isolated keys

For a public tweak, anyone holding the child private scalar can calculate:

```text
parent private scalar = (child private scalar - tweak) mod n
```

In x-only mode, this recovers the normalized parent scalar, which is sufficient
to control that x-only identity and derive its other children. Therefore a leak
of one child secret can compromise the entire related family. A public prefix
or hashed domain does not prevent this.

The public relationship is also discoverable: someone with the parent public
key can test likely domain names and identify corresponding child keys. Distinct
keys do not automatically mean unlinkable identities. Knowing a public child
key alone does not reveal its private key.

| Requirement | Appropriate direction |
| --- | --- |
| Derive child public keys from a public parent and context | These additive tweaks |
| Protect the parent and sibling keys if one child secret leaks | Hardened derivation or a reviewed secret-based KDF design |
| Avoid a shared derivation root | Independently generated keys with separate storage and backups |
| Post-quantum signatures | Stroma's separate experimental PQ backend, not secp256k1 tweaks |

[BIP-32 hardened derivation](https://bips.dev/32/) is an established hierarchical
approach using extended keys and chain codes. An alternative application design
can use [HKDF](https://www.rfc-editor.org/rfc/rfc5869) with high-entropy secret
input and explicit domain context, but mapping output to valid private scalars
and specifying retries still require a reviewed protocol. Neither approach is
implemented by Stroma's `tweak_add()` methods, and hardened child public keys
cannot be derived from the parent public key alone. A compromised master still
compromises its derived keys.

The existing parent private key could supply secret input to a separately
designed KDF, or an application could maintain a dedicated random master seed.
That is a separate design decision, not an extra secret automatically created
by `tweak_add()`.

## Rotation and long-lived verification

Preserve the derivation version, canonical context, parent public identity,
x-only mode, and any explicitly specified retry counter alongside verification
metadata. These public inputs let future verifiers reconstruct the expected
key. Keep historical parent public keys when rotating parents.

An epoch or version in the context creates another key but does not revoke
older keys, erase their signatures, or isolate compromises. Applications still
need rotation, trusted-time, retention, and revocation policies appropriate to
their records. These secp256k1 operations remain classical even if an external
post-quantum attestation refers to the derived identity.
