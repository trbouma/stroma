import pytest

from stroma import BasicKeySigner, Event, GiftWrap, GiftWrapError, Keys


@pytest.mark.asyncio
async def test_gift_wrap_round_trip_preserves_inner_kind() -> None:
    sender = Keys()
    recipient = Keys()
    inner = Event(kind=7378, content="opaque Acorn payload", tags=[["x", "1"]], created_at=10)

    wrapped, ephemeral = await GiftWrap(BasicKeySigner(sender)).wrap(
        inner,
        recipient,
        expiration=1234,
    )
    recovered = await GiftWrap(BasicKeySigner(recipient)).unwrap(wrapped)

    assert wrapped.kind == 1059
    assert wrapped.pub_key == ephemeral.public_key_hex()
    assert wrapped.tags.get_tag_value_pos("expiration") == "1234"
    assert recovered.kind == 7378
    assert recovered.content == inner.content
    assert recovered.pub_key == sender.public_key_hex()
    assert recovered.sig is None


@pytest.mark.asyncio
async def test_wrong_recipient_is_rejected() -> None:
    wrapped, _ = await GiftWrap(BasicKeySigner(Keys())).wrap(Event(content="x"), Keys())

    with pytest.raises(GiftWrapError):
        await GiftWrap(BasicKeySigner(Keys())).unwrap(wrapped)


@pytest.mark.asyncio
async def test_zero_jitter_uses_current_timestamp(monkeypatch) -> None:
    monkeypatch.setattr("stroma.nip59.time.time", lambda: 500)
    wrapped, _ = await GiftWrap(BasicKeySigner(Keys()), jitter_seconds=0).wrap(
        Event(content="x", created_at=10), Keys()
    )

    assert wrapped.created_at == 500


@pytest.mark.asyncio
async def test_legacy_rumour_kind_can_be_requested() -> None:
    sender = Keys()
    recipient = Keys()
    gift_wrap = GiftWrap(BasicKeySigner(sender), preserve_rumour_kind=False)

    wrapped, _ = await gift_wrap.wrap(Event(kind=7378, content="x"), recipient)
    recovered = await GiftWrap(BasicKeySigner(recipient)).unwrap(wrapped)

    assert recovered.kind == Event.KIND_RUMOUR
