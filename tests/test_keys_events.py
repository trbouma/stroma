from stroma import Event, Keys


def test_key_round_trip() -> None:
    keys = Keys()
    recovered = Keys(priv_k=keys.private_key_bech32())

    assert recovered.private_key_hex() == keys.private_key_hex()
    assert recovered.public_key_hex() == keys.public_key_hex()
    assert Keys(pub_k=keys.public_key_bech32()).public_key_hex() == keys.public_key_hex()


def test_event_sign_and_validate() -> None:
    keys = Keys(priv_k="1".zfill(64))
    event = Event(kind=1, content="Stroma", tags=[["t", "wire-format"]], created_at=1)

    event.sign(keys)

    assert event.is_valid()
    assert Event.load(event.data(), validate=True) is not None


def test_event_tampering_fails_validation() -> None:
    event = Event(kind=1, content="before", created_at=1)
    event.sign(Keys())
    event.content = "after"

    assert not event.is_valid()


def test_event_id_is_canonical() -> None:
    event = Event(
        kind=1,
        content="hello",
        tags=[],
        pub_key="79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        created_at=1,
    )

    assert event.serialize() == '[0,"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",1,1,[],"hello"]'
