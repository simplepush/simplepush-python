"""Connection teardown against a live backend.

The server side doesn't always answer the WebSocket close frame; with the
websockets library's default close_timeout, `aclose()` then blocked for a full
10 seconds. The SDK caps the wait at 1 second — this pins that."""

import asyncio
import time

from simplepush import Client


def test_aclose_returns_promptly_after_streaming(conn):
    client = Client(**conn)

    async def go():
        async def consume():
            async for _ in client.events():
                pass

        task = asyncio.create_task(consume())
        await asyncio.sleep(2.0)  # let the socket connect and idle

        start = time.monotonic()
        await client.aclose()
        took = time.monotonic() - start
        assert took < 3.0, f"aclose took {took:.2f}s — close-frame wait is back (was 10s)"

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    asyncio.run(go())
