# secp256k1 Curve Primitives

Stroma exposes `CurvePoint` and `CURVE_ORDER` for applications that need
secp256k1 point arithmetic without importing coincurve directly. These APIs
are included in the default installation; no optional extra is required.

```text
Application protocol logic
    → Stroma CurvePoint
        → coincurve
            → libsecp256k1
```

## API

Import both names from the public package:

```python
from stroma import CURVE_ORDER, CurvePoint
```

| Operation | Result |
| --- | --- |
| `CurvePoint(encoded)` | Parse compressed or uncompressed SEC1 bytes |
| `CurvePoint.from_scalar(scalar)` | Multiply the curve generator by a scalar |
| `CurvePoint.combine(points)` | Add a nonempty sequence of points |
| `CurvePoint.from_xonly(encoded)` | Lift a 32-byte x-only public key to even Y |
| `point.tweak_add(digest, x_only=False)` | Add a digest times the generator, returning a new point |
| `Keys.tweak_add(digest, x_only=False)` | Derive a new private/public keypair from a private-bearing `Keys` instance |
| `point.multiply(scalar)` | Multiply a point by a scalar |
| `point.format()` | Serialize to 33-byte compressed SEC1 bytes |
| `point.format(compressed=False)` | Serialize to 65-byte uncompressed SEC1 bytes |
| `CURVE_ORDER` | Integer order of the secp256k1 scalar group |

Scalars must be `bytes` of exactly 32 bytes, encoded in big-endian order, with
an integer value from `1` through `CURVE_ORDER - 1`. Values are not implicitly
reduced modulo the order. Invalid scalar values, malformed point encodings,
an empty sum, and results at infinity raise `ValueError`.

Arithmetic returns new points without changing the input points. Point objects
do not retain the private scalar supplied to an operation; this is not a promise
of secure erasure of Python memory.

## Point arithmetic example

The small scalars below are public examples, not keys for operational use.

```python
from stroma import CurvePoint

one = (1).to_bytes(32, "big")
two = (2).to_bytes(32, "big")
generator = CurvePoint.from_scalar(one)

assert generator.format().hex() == (
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
assert generator.multiply(two).format() == CurvePoint.combine(
    [generator, generator]
).format()

encoded = generator.format(compressed=False)
assert CurvePoint(encoded).format() == generator.format()
```

## SEC1 points and Nostr keys

`CurvePoint` preserves the full point, including its parity. Compressed SEC1
encoding is 33 bytes with a `02` or `03` prefix; uncompressed encoding is 65
bytes with a `04` prefix. Hybrid encodings and raw 32-byte x-only keys are not
accepted by the `CurvePoint` constructor. Use `CurvePoint.from_xonly()`
explicitly to lift an x-only key to its even-Y point.

Use `Keys` and `Event` for Nostr key handling and event signatures. Converting
between x-only keys and full points requires the calling protocol's parity
rules; do not silently discard or invent that information.

## Additive key tweaks from a SHA-256 digest

`Keys.tweak_add()` derives a new keypair without modifying the original.
`CurvePoint.tweak_add()` derives the corresponding public point without needing
its private key. Both accept an **already computed digest**, not a message or
hex string; Stroma does not hash it again.

For a private key `d`, public point `P = dG`, and big-endian digest integer `t`:

```text
d' = (d + t) mod n
P' = P + tG
```

Tweaks must be exactly 32 bytes and less than `CURVE_ORDER`. Unlike private
scalars, a zero tweak is allowed (it leaves the normalized input unchanged).
Out-of-range tweaks, a zero derived secret, and a public result at infinity
raise `ValueError`. Inputs are never silently reduced modulo the order.
Calling `Keys.tweak_add()` on a public-only `Keys` raises Stroma's `KeyError`.

```python
import hashlib
from stroma import CurvePoint, Keys

parent = Keys()
# Example application domain; choose a stable, unambiguous encoding in your protocol.
digest = hashlib.sha256(b"example/key-derivation/v1:record-42").digest()
child = parent.tweak_add(digest)

parent_point = CurvePoint.from_scalar(bytes.fromhex(parent.private_key_hex()))
child_point = parent_point.tweak_add(digest)
assert child_point.format() == CurvePoint.from_scalar(
    bytes.fromhex(child.private_key_hex())
).format()
```

### X-only derivation

Use `x_only=True` when public derivation starts with a Nostr/BIP-340-style
x-only key. Before adding the tweak, Stroma normalizes the parent point to
even Y and, if necessary, replaces its private scalar `d` with `n - d` using
the native curve library. This makes private and public derivation agree.

```python
x_child = parent.tweak_add(digest, x_only=True)
public_parent = CurvePoint.from_xonly(bytes.fromhex(parent.public_key_hex()))
public_child = public_parent.tweak_add(digest)

assert public_child.format()[1:].hex() == x_child.public_key_hex()
assert public_child.format() == CurvePoint.from_scalar(
    bytes.fromhex(x_child.private_key_hex())
).format()
```

The **output is not normalized**: the returned secret corresponds to the actual
output point, whose compressed prefix preserves its parity. `02` means even Y;
`03` means odd Y. For another x-only derivation step, normalize again by using
`x_only=True` or lifting the new x-only key with `from_xonly()`.

This is an experimental general primitive, not a complete Taproot or wallet
key-derivation protocol. Applications choose the digest construction, domain
separation, encoding, and invalid-result handling. A public tweak and a leaked
derived private key reveal the parent scalar (the normalized parent in x-only
mode); this provides no hardened child-key isolation. Do not log private keys.

## Clear integration and component boundary

Clear uses these primitives for the curve operations underlying its Cashu
blind signatures. Clear remains responsible for:

- Cashu hash-to-curve and its domain separator;
- denomination key derivation and CMU/keyset identity;
- blinding, unblinding, and proof verification;
- issuance authorization, spent-state tracking, and accounting.

Stroma provides general point operations and owns the coincurve dependency.
It does not interpret Cashu proofs or become a mint or wallet. The same
underlying curve library supports Stroma's Nostr operations, but Nostr Schnorr
signatures and Cashu blind signatures remain different protocol constructions.

Consumers should pin a tested Stroma commit containing this API and regenerate
their dependency lock file. Editing a sibling Stroma checkout does not change
an already installed dependency. Clear's migration includes a fixed regression
vector for existing keyset identity and signature output.

See the [protocol surface](protocol-surface.md) and
[security commitments](security.md) for the wider library boundary.

For application patterns, domain-key examples, and compromise boundaries, see
[Using Key Tweaks](key-tweaking-guide.md).
