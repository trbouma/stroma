from stroma import Entities, Keys


def test_simple_entities_round_trip() -> None:
    public_hex = Keys(priv_k="1".zfill(64)).public_key_hex()
    encoded = Entities.encode("npub", public_hex)

    assert Entities.decode(encoded) == public_hex


def test_nprofile_round_trip() -> None:
    public_hex = Keys(priv_k="2".zfill(64)).public_key_hex()
    encoded = Entities.encode(
        "nprofile",
        {"pubkey": public_hex, "relay": ["wss://one.example", "wss://two.example"]},
    )

    assert Entities.decode(encoded) == {
        "pubkey": public_hex,
        "relay": ["wss://one.example", "wss://two.example"],
    }
