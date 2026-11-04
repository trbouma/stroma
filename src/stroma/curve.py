"""Protocol-neutral secp256k1 point operations backed by coincurve.

Points use SEC1 encoding, including parity; they are not Nostr x-only keys.
Invalid encodings, scalars, and results at infinity raise ValueError.
"""

from __future__ import annotations

from collections.abc import Sequence

from coincurve import PrivateKey, PublicKey

CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def _scalar(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError("scalar must be exactly 32 bytes")
    if not 0 < int.from_bytes(value, "big") < CURVE_ORDER:
        raise ValueError("scalar must be between 1 and the curve order minus 1")
    return value


def _tweak(value: bytes) -> bytes:
    if not isinstance(value, bytes) or len(value) != 32:
        raise ValueError("tweak must be exactly 32 bytes")
    if int.from_bytes(value, "big") >= CURVE_ORDER:
        raise ValueError("tweak must be less than the curve order")
    return value


class CurvePoint:
    """An immutable-by-API secp256k1 point, with no protocol semantics."""

    def __init__(self, encoded: bytes):
        if not isinstance(encoded, bytes) or not (
            (len(encoded) == 33 and encoded[0] in (2, 3))
            or (len(encoded) == 65 and encoded[0] == 4)
        ):
            raise ValueError("point must be compressed or uncompressed SEC1 bytes")
        self._point = PublicKey(encoded)

    @classmethod
    def from_scalar(cls, scalar: bytes) -> CurvePoint:
        """Return scalar times the generator; never retain the private scalar."""
        return cls(PrivateKey(_scalar(scalar)).public_key.format(compressed=True))

    @classmethod
    def combine(cls, points: Sequence[CurvePoint]) -> CurvePoint:
        """Add a nonempty sequence of points; reject a result at infinity."""
        if not points:
            raise ValueError("at least one point is required")
        return cls(PublicKey.combine_keys([p._point for p in points]).format())

    def multiply(self, scalar: bytes) -> CurvePoint:
        """Return a new point multiplied by a nonzero canonical scalar."""
        return type(self)(self._point.multiply(_scalar(scalar)).format())

    def format(self, compressed: bool = True) -> bytes:
        """Serialize as SEC1 bytes (compressed by default)."""
        return self._point.format(compressed=compressed)

    @classmethod
    def from_xonly(cls, encoded: bytes) -> CurvePoint:
        """Lift a 32-byte x-only key to its even-Y SEC1 point."""
        if not isinstance(encoded, bytes) or len(encoded) != 32:
            raise ValueError("x-only key must be exactly 32 bytes")
        return cls(b"\x02" + encoded)

    def tweak_add(self, digest: bytes, *, x_only: bool = False) -> CurvePoint:
        """Return P + tG, optionally normalizing P to even Y first.

        digest is an already computed 32-byte digest, interpreted big-endian.
        Zero is allowed; out-of-range tweaks and infinity are rejected.
        The result retains its actual parity, even in x-only mode.
        """
        tweak = _tweak(digest)
        point = self._point
        if x_only:
            point = PublicKey(b"\x02" + self.format()[1:])
        return type(self)(point.add(tweak, update=False).format())
