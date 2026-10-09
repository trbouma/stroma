import asyncio
import base64
import hashlib
import json
from contextlib import asynccontextmanager

import pytest
from aiohttp import web

from stroma import BlossomError, BlossomPool, Event, Keys, storage_threshold
from stroma.blossom import _PublicResolver


@pytest.mark.parametrize("count,expected", [(1, (1, 1, 1, 1)), (2, (1, 1, 2, 2)), (3, (1, 2, 2, 3)), (4, (1, 2, 3, 4)), (5, (1, 3, 3, 5))])
def test_thresholds(count, expected):
    assert tuple(storage_threshold(count, mode) for mode in ("any", "half", "majority", "all")) == expected


def test_validation_and_deduplication():
    assert BlossomPool(["https://EXAMPLE.com/", "https://example.com:443"]).servers == ("https://example.com",)
    for servers in ([], ["http://example.com"], ["https://127.0.0.1"], ["https://[::1]"], ["https://169.254.169.254"], ["https://user@example.com"], ["https://example.com/path"], ["https://example.com?q=1"]):
        with pytest.raises(ValueError):
            BlossomPool(servers)
    for options in ({"timeout": 0}, {"concurrency": 0}, {"max_bytes": -1}, {"operation_timeout": float("inf")}):
        with pytest.raises(ValueError):
            BlossomPool(["https://example.com"], **options)
    with pytest.raises(ValueError):
        storage_threshold(0)
    with pytest.raises(ValueError):
        storage_threshold(2, "unknown")


@asynccontextmanager
async def server(mode="ok", content=None):
    state = {"content": content, "uploads": 0, "tokens": [], "gets": 0}

    async def get(request):
        state["gets"] += 1
        if mode == "slow":
            await asyncio.sleep(.3)
        if mode == "redirect":
            raise web.HTTPFound("http://127.0.0.1:1/private")
        if mode == "wrong":
            return web.Response(body=b"wrong")
        if state["content"] is None:
            raise web.HTTPNotFound()
        return web.Response(body=state["content"], content_type="application/pdf")

    async def upload(request):
        state["uploads"] += 1
        token = request.headers["Authorization"].split(" ", 1)[1]
        assert "=" not in token
        event = Event.load(json.loads(base64.urlsafe_b64decode(token + "=" * (-len(token) % 4))), validate=True)
        assert event is not None and event.kind == 24242
        state["tokens"].append(event)
        body = await request.read()
        assert event.tags.get_tags_value("x") == [hashlib.sha256(body).hexdigest()]
        assert event.tags.get_tags_value("server") == ["127.0.0.1"]
        if mode == "reject":
            raise web.HTTPForbidden()
        if mode != "fake":
            state["content"] = body
        if mode == "lost_response":
            await asyncio.sleep(.15)
        return web.json_response({"sha256": hashlib.sha256(body).hexdigest()}, status=201)

    app = web.Application()
    app.router.add_put("/upload", upload)
    app.router.add_get("/{digest}", get)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    url = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
    try:
        yield url, state
    finally:
        await runner.cleanup()


def pool(servers, **options):
    return BlossomPool(servers, allow_http=True, allow_private=True, **options)


def test_server_limit_counts_normalized_unique_origins():
    duplicates = ["https://EXAMPLE.com/", "https://example.com:443"] * 40
    assert BlossomPool(duplicates, max_servers=1).servers == ("https://example.com",)
    assert BlossomPool(
        [*duplicates, "https://backup.example.com", *duplicates], max_servers=2,
    ).servers == ("https://example.com", "https://backup.example.com")
    with pytest.raises(ValueError, match="Too many unique"):
        BlossomPool([*duplicates, "https://backup.example.com"], max_servers=1)
    # Reaching the unique limit must not skip validation of subsequent entries.
    with pytest.raises(ValueError):
        BlossomPool([*duplicates, "http://example.com"], max_servers=1)


@pytest.mark.asyncio
async def test_retrieve_deduplicates_configured_servers_and_hints_before_limit():
    content = b"verified artifact"
    digest = hashlib.sha256(content).hexdigest()
    async with server(content=content) as (url, state):
        result = await pool([url, url + "/"], max_servers=1).retrieve(
            digest, hints=[url, url + "/"] * 40,
        )
        assert result.content == content
        assert state["gets"] == 1
        with pytest.raises(ValueError, match="Too many unique"):
            await pool([url], max_servers=1).retrieve(
                digest, hints=["http://127.0.0.1:1"],
            )
        assert state["gets"] == 1  # Reject an oversized union before network I/O.


@pytest.mark.asyncio
async def test_store_default_any_and_all_outcomes():
    async with server() as (good, good_state), server("reject") as (bad, bad_state):
        result = await pool([good, bad, good]).store(b"artifact", signer=Keys())
        assert result.ok and result.required == 1 and result.require == "any"
        assert result.confirmed_servers == (good,)
        assert [item.status for item in result.outcomes] == ["confirmed", "rejected"]
        assert good_state["uploads"] == bad_state["uploads"] == 1
        assert result.digest == hashlib.sha256(b"artifact").hexdigest()
        for mode, ok in (("half", True), ("majority", False), ("all", False)):
            result = await pool([good, bad]).store(b"artifact", signer=Keys(), require=mode)
            assert result.ok is ok
        assert good_state["uploads"] == 1  # Existing verified bytes are not re-uploaded.


@pytest.mark.asyncio
async def test_lost_upload_response_is_reconciled_without_retry():
    async with server("lost_response") as (url, state):
        result = await pool([url], timeout=.05).store(b"artifact", signer=Keys())
        assert result.ok
        assert state["uploads"] == 1


@pytest.mark.asyncio
async def test_false_success_is_not_confirmation():
    async with server("fake") as (url, state):
        result = await pool([url]).store(b"artifact", signer=Keys())
        assert not result.ok and result.outcomes[0].status == "unconfirmed"


@pytest.mark.asyncio
async def test_retrieve_fallback_hints_and_wrong_digest():
    content = b"verified artifact"
    digest = hashlib.sha256(content).hexdigest()
    async with server("wrong") as (bad, _), server(content=content) as (good, _):
        result = await pool([bad], max_servers=2).retrieve(digest, hints=[good, bad, good])
        assert result.content == content and result.server == good
        assert result.media_type == "application/pdf"
        with pytest.raises(BlossomError) as failure:
            await pool([bad]).retrieve(digest)
        assert "SHA-256" in failure.value.outcomes[0].message


@pytest.mark.asyncio
async def test_limits_redirects_and_deadlines():
    content = b"abcdef"
    digest = hashlib.sha256(content).hexdigest()
    async with server(content=content) as (url, _):
        with pytest.raises(BlossomError):
            await pool([url], max_bytes=2).retrieve(digest)
        with pytest.raises(ValueError):
            await pool([url], max_bytes=2).store(content, signer=Keys())
    async with server("redirect") as (url, _):
        with pytest.raises(BlossomError) as failure:
            await pool([url]).retrieve(digest)
        assert "302" in failure.value.outcomes[0].message
    async with server("slow", content=content) as (url, _):
        with pytest.raises(BlossomError):
            await pool([url], operation_timeout=.03).retrieve(digest)
        result = await pool([url], operation_timeout=.03).store(content, signer=Keys())
        assert not result.ok and result.outcomes[0].status == "unconfirmed"


@pytest.mark.asyncio
async def test_first_verified_copy_cancels_remaining_workers(monkeypatch):
    instance = BlossomPool(["https://fast.example", "https://slow.example"])
    started, cancelled = asyncio.Event(), asyncio.Event()
    from stroma import BlossomRetrievalResult

    async def get(session, url, digest):
        if "slow" in url:
            started.set()
            try:
                await asyncio.sleep(30)
            finally:
                cancelled.set()
        await started.wait()
        return BlossomRetrievalResult(digest, b"a", url, "text/plain")

    monkeypatch.setattr(instance, "_get", get)
    await instance.retrieve(hashlib.sha256(b"a").hexdigest())
    assert cancelled.is_set()


@pytest.mark.asyncio
async def test_dns_private_destination_blocked(monkeypatch):
    resolver = _PublicResolver()
    async def resolve(*args):
        return [{"host": "127.0.0.1"}]
    monkeypatch.setattr(resolver.resolver, "resolve", resolve)
    with pytest.raises(OSError):
        await resolver.resolve("public-looking.example", 443)
    await resolver.close()


@pytest.mark.asyncio
async def test_retrieval_concurrency_and_caller_cancellation(monkeypatch):
    instance = BlossomPool([f"https://s{i}.example" for i in range(6)], concurrency=2)
    active, peak = 0, 0
    ready = asyncio.Event()

    async def get(*args):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        if active == 2:
            ready.set()
        try:
            await asyncio.sleep(30)
        finally:
            active -= 1

    monkeypatch.setattr(instance, "_get", get)
    task = asyncio.create_task(instance.retrieve("a" * 64))
    await asyncio.wait_for(ready.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert peak == 2 and active == 0


@pytest.mark.asyncio
async def test_store_cancellation_during_signing(monkeypatch):
    instance = BlossomPool(["https://s1.example", "https://s2.example"])
    ready = asyncio.Event()
    async def missing(*args):
        raise BlossomError("Missing")
    async def authorize(*args):
        ready.set()
        await asyncio.sleep(30)
    monkeypatch.setattr(instance, "_get", missing)
    monkeypatch.setattr(instance, "_authorization", authorize)
    task = asyncio.create_task(instance.store(b"bytes", signer=Keys()))
    await asyncio.wait_for(ready.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
