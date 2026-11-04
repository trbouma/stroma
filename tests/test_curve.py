import pytest

from stroma import CURVE_ORDER, CurvePoint

G = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
TWO_G = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"


def scalar(n):
    return n.to_bytes(32, "big")


def test_known_points_and_nonmutating_arithmetic():
    g = CurvePoint.from_scalar(scalar(1))
    assert g.format().hex() == G
    assert g.multiply(scalar(2)).format().hex() == TWO_G
    assert CurvePoint.combine([g, g]).format().hex() == TWO_G
    assert g.format().hex() == G
    assert CurvePoint(g.format(compressed=False)).format() == g.format()


@pytest.mark.parametrize(
    "value",
    [b"", b"\x01", bytes(32), bytes(33), scalar(CURVE_ORDER), scalar(2**256 - 1)],
)
def test_invalid_scalars(value):
    with pytest.raises(ValueError):
        CurvePoint.from_scalar(value)
    with pytest.raises(ValueError):
        CurvePoint(bytes.fromhex(G)).multiply(value)


@pytest.mark.parametrize(
    "encoded", [b"", bytes(32), b"\x02" + b"\xff" * 32, b"\x04" + bytes(64)]
)
def test_invalid_points(encoded):
    with pytest.raises(ValueError):
        CurvePoint(encoded)


def test_infinity_and_empty_sum_rejected():
    g = CurvePoint(bytes.fromhex(G))
    with pytest.raises(ValueError):
        CurvePoint.combine([])
    with pytest.raises(ValueError):
        CurvePoint.combine([g, g.multiply(scalar(CURVE_ORDER - 1))])
