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
accepted by this API.

Use `Keys` and `Event` for Nostr key handling and event signatures. Converting
between x-only keys and full points requires the calling protocol's parity
rules; do not silently discard or invent that information.

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
