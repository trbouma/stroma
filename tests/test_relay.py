import json

import pytest
from aiohttp import WSMsgType, web

from stroma import Event, Keys, RelayClient


@pytest.mark.asyncio
async def test_publish_acknowledgement_and_query_eose() -> None:
    stored: list[dict] = []

    async def relay(request: web.Request) -> web.WebSocketResponse:
        websocket = web.WebSocketResponse()
        await websocket.prepare(request)
        async for message in websocket:
            if message.type is not WSMsgType.TEXT:
                continue
            command = json.loads(message.data)
            if command[0] == "EVENT":
                stored.append(command[1])
                await websocket.send_json(["OK", command[1]["id"], True, "stored"])
            elif command[0] == "REQ":
                subscription_id = command[1]
                for event in stored:
                    await websocket.send_json(["EVENT", subscription_id, event])
                await websocket.send_json(["EOSE", subscription_id])
            elif command[0] == "CLOSE":
                await websocket.close()
        return websocket

    application = web.Application()
    application.router.add_get("/", relay)
    runner = web.AppRunner(application)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    sockets = site._server.sockets  # type: ignore[union-attr]
    url = f"ws://127.0.0.1:{sockets[0].getsockname()[1]}"

    try:
        event = Event(kind=1, content="relay test")
        event.sign(Keys())
        result = await RelayClient(url).publish(event)
        queried = await RelayClient(url).query({"ids": [event.id]})

        assert result.accepted
        assert result.message == "stored"
        assert [item.id for item in queried] == [event.id]
    finally:
        await runner.cleanup()
