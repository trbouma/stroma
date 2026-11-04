import hashlib

import pytest
from coincurve import PublicKeyXOnly

from stroma import CURVE_ORDER, CurvePoint, Event, Keys
from stroma import KeyError as StromaKeyError


def scalar(value):
    return value.to_bytes(32, "big")


@pytest.mark.parametrize("secret", [1, 6, CURVE_ORDER - 1])
@pytest.mark.parametrize("x_only", [False, True])
def test_digest_tweak_private_public_agree(secret, x_only):
    parent = Keys(priv_k=scalar(secret).hex())
    digest = hashlib.sha256(b"stroma/test/key-tweak/v1").digest()
    point = CurvePoint.from_scalar(scalar(secret))
    original = point.format()
    child = parent.tweak_add(digest, x_only=x_only)
    public = point.tweak_add(digest, x_only=x_only)
    assert (
        CurvePoint.from_scalar(bytes.fromhex(child.private_key_hex())).format()
        == public.format()
    )
    assert parent.private_key_hex() == scalar(secret).hex()
    assert point.format() == original
    assert child.private_key_hex() != parent.private_key_hex()
    event = Event(kind=1, content="derived-key test")
    event.sign(child)
    assert event.is_valid()
    if x_only:
        lifted = CurvePoint.from_xonly(bytes.fromhex(parent.public_key_hex()))
        assert lifted.tweak_add(digest).format() == public.format()
        reference = PublicKeyXOnly(bytes.fromhex(parent.public_key_hex()))
        reference.tweak_add(digest)
        assert reference.format() == bytes.fromhex(child.public_key_hex())
        assert reference.parity == (public.format()[0] == 3)


def test_known_addition_and_odd_parent_normalization():
    parent = Keys(priv_k=scalar(1).hex())
    assert parent.tweak_add(scalar(1)).private_key_hex() == scalar(2).hex()
    odd = Keys(priv_k=scalar(CURVE_ORDER - 1).hex())
    assert CurvePoint.from_scalar(scalar(CURVE_ORDER - 1)).format()[0] == 3
    assert odd.tweak_add(scalar(1), x_only=True).private_key_hex() == scalar(2).hex()
    with pytest.raises(ValueError):
        odd.tweak_add(scalar(1))


@pytest.mark.parametrize("x_only", [False, True])
def test_zero_tweak_and_infinity(x_only):
    parent = Keys(priv_k=scalar(1).hex())
    point = CurvePoint.from_scalar(scalar(1))
    assert (
        parent.tweak_add(bytes(32), x_only=x_only).private_key_hex()
        == parent.private_key_hex()
    )
    assert point.tweak_add(bytes(32), x_only=x_only).format() == point.format()
    with pytest.raises(ValueError):
        parent.tweak_add(scalar(CURVE_ORDER - 1), x_only=x_only)
    with pytest.raises(ValueError):
        point.tweak_add(scalar(CURVE_ORDER - 1), x_only=x_only)


@pytest.mark.parametrize(
    "digest",
    [
        b"",
        bytes(31),
        bytes(33),
        scalar(CURVE_ORDER),
        scalar(2**256 - 1),
        "00" * 32,
        None,
    ],
)
def test_invalid_tweaks(digest):
    with pytest.raises(ValueError):
        Keys(priv_k=scalar(1).hex()).tweak_add(digest)
    with pytest.raises(ValueError):
        CurvePoint.from_scalar(scalar(1)).tweak_add(digest)


@pytest.mark.parametrize(
    "encoded", [b"", bytes(31), bytes(33), b"\xff" * 32, "00" * 32]
)
def test_invalid_xonly_points(encoded):
    with pytest.raises(ValueError):
        CurvePoint.from_xonly(encoded)


def test_public_only_key_cannot_derive_private_key():
    parent = Keys(priv_k=scalar(1).hex())
    with pytest.raises(StromaKeyError):
        Keys(pub_k=parent.public_key_hex()).tweak_add(scalar(1))
