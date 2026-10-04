#!/usr/bin/env python3
"""Demo origin for cf-tunnel-bridge smoke tests.

HTTP  GET /health  -> public, "ok <timestamp>"
WS    /ws          -> shared-key auth (header X-Bridge-Key or ?key=),
                      server greeting on connect, echo per message,
                      "push-after:N" schedules a server push N seconds
                      later on the same socket.
WS without a valid key is closed immediately with code 4401 (an HTTP
401 on the upgrade is mangled into a 502 by the tunnel, so don't).

Key and port come from argv/env; the key is never logged.
    python3 demo_origin.py --port 18099 --key-file secrets/bridge-key.txt
Requires: websockets (pip install websockets, or the project venv).
"""
from __future__ import annotations

import argparse
import asyncio
import datetime
import urllib.parse

import websockets
from websockets.datastructures import Headers
from websockets.http11 import Response

KEY = ""


def now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def key_ok(request) -> bool:
    if request.headers.get("X-Bridge-Key") == KEY:
        return True
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(request.path).query)
    return qs.get("key", [""])[0] == KEY


async def process_request(connection, request):
    path = urllib.parse.urlparse(request.path).path
    if path == "/health":
        body = f"ok {now()}\n".encode()
        return Response(200, "OK", Headers([("Content-Type", "text/plain")]), body)
    if path != "/ws":
        body = b"demo origin: use /health or /ws\n"
        return Response(404, "Not Found", Headers([("Content-Type", "text/plain")]), body)
    return None


async def handler(ws):
    if not key_ok(ws.request):
        await ws.close(code=4401, reason="unauthorized")
        return
    await ws.send(f"server-greeting {now()}")
    async for msg in ws:
        if msg.startswith("push-after:"):
            try:
                secs = float(msg.split(":", 1)[1])
            except ValueError:
                secs = 1.0

            async def later():
                await asyncio.sleep(secs)
                try:
                    await ws.send(f"server-push {now()}")
                except Exception:  # noqa: BLE001
                    pass

            asyncio.create_task(later())
            await ws.send(f"scheduled push in {secs}s")
        else:
            await ws.send(f"echo:{msg}")


async def main(port: int) -> None:
    async with websockets.serve(handler, "127.0.0.1", port, process_request=process_request):
        print(f"demo origin on 127.0.0.1:{port} (auth on /ws)", flush=True)
        await asyncio.Future()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18099)
    ap.add_argument("--key-file", required=True)
    args = ap.parse_args()
    with open(args.key_file, encoding="utf-8") as f:
        KEY = f.read().strip()
    if not KEY:
        raise SystemExit(f"empty bridge key: {args.key_file}")
    asyncio.run(main(args.port))
