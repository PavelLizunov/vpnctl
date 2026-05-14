#!/usr/bin/env python3
"""Visual-check helper — drives a headless Chrome instance over CDP to
capture full-page PNG screenshots of vpnctld admin pages.

WHY THIS EXISTS
---------------
The admin_smoke tests assert HTML substrings, classes, and routing.
They cannot catch:

  - floating panels overlapping page content,
  - long opaque tokens (SHA256, base64) escaping their grid track,
  - misaligned columns at common viewports,
  - regressions in the editorial chrome (masthead, nav, footer).

This script is the third leg of the SITE methodology — paired with
`cargo test` (DOM-level smoke) and `cargo clippy` (static checks). Run
it manually after any user-visible UI change; commit the resulting
screenshots only when intentionally documenting a redesign.

USAGE
-----
    python3 scripts/visual_check.py <url> <out.png> [user:pass] [cookie]

Requires: a running headless Chrome with CDP listening on
`http://192.168.0.142:9222` (the homelab Chrome instance), and Python
package `websockets` (≥ 12).

EXAMPLE
-------
    ADMIN_PW=$(grep VPNCTLD_ADMIN_PASSWORD inventory/vpnctld-192.168.0.236.env | cut -d= -f2)
    python3 scripts/visual_check.py \
        http://192.168.0.236:18402/admin/users /tmp/users.png "slovn:${ADMIN_PW}"

    # collapsed Tweaks panel:
    python3 scripts/visual_check.py \
        http://192.168.0.236:18402/admin/ /tmp/dash.png "slovn:${ADMIN_PW}" \
        "vpnctl_tweaks=closed"

NOTES
-----
- Reuses a persistent Chrome tab (Chrome ≥ 130 dropped the GET form of
  `/json/new`); after each shot the tab is reset to about:blank.
- Disables the network cache before every shot so CSS-only changes are
  reflected immediately. Otherwise the second screenshot of a page
  silently uses the previous render.
- `Network.setExtraHTTPHeaders` is used both for basic-auth and the
  optional cookie — that way the admin-side cookie parser sees
  exactly what a real browser would send.
"""

import asyncio
import base64
import json
import sys
import urllib.request

import websockets

CDP_HTTP = "http://192.168.0.142:9222"


async def cdp_call(ws, msg_id: int, method: str, params: dict | None = None):
    await ws.send(json.dumps({"id": msg_id, "method": method, "params": params or {}}))
    while True:
        raw = await ws.recv()
        msg = json.loads(raw)
        if msg.get("id") == msg_id:
            if "error" in msg:
                raise RuntimeError(f"{method} → {msg['error']}")
            return msg.get("result", {})


async def wait_event(ws, name: str, max_msgs: int = 200):
    for _ in range(max_msgs):
        raw = await ws.recv()
        msg = json.loads(raw)
        if msg.get("method") == name:
            return msg.get("params", {})
    raise RuntimeError(f"never saw {name}")


async def shoot(
    url: str,
    out_path: str,
    basic_auth: str | None,
    viewport: tuple[int, int] = (1280, 900),
    extra_cookie: str | None = None,
) -> None:
    tabs = json.loads(urllib.request.urlopen(f"{CDP_HTTP}/json").read())
    page_tab = next((t for t in tabs if t.get("type") == "page"), None)
    if page_tab is None:
        raise RuntimeError("no page-type tab available — start headless Chrome first")
    ws_url = page_tab["webSocketDebuggerUrl"]

    try:
        async with websockets.connect(ws_url, max_size=20 * 1024 * 1024) as ws:
            await cdp_call(ws, 1, "Page.enable")
            await cdp_call(ws, 2, "Network.enable")
            await cdp_call(ws, 3, "Network.setCacheDisabled", {"cacheDisabled": True})
            await cdp_call(ws, 4, "Network.clearBrowserCache")

            headers: dict[str, str] = {}
            if basic_auth:
                token = base64.b64encode(basic_auth.encode()).decode()
                headers["Authorization"] = f"Basic {token}"
            if extra_cookie:
                headers["Cookie"] = extra_cookie
            if headers:
                await cdp_call(ws, 5, "Network.setExtraHTTPHeaders", {"headers": headers})

            await cdp_call(
                ws,
                6,
                "Emulation.setDeviceMetricsOverride",
                {
                    "width": viewport[0],
                    "height": viewport[1],
                    "deviceScaleFactor": 1,
                    "mobile": False,
                },
            )
            await cdp_call(ws, 7, "Page.navigate", {"url": url})
            await wait_event(ws, "Page.loadEventFired")
            # Tiny settle for fonts (the admin shell pulls Newsreader +
            # IBM Plex from Google Fonts — first paint can race the swap).
            await asyncio.sleep(0.4)
            res = await cdp_call(
                ws,
                8,
                "Page.captureScreenshot",
                {"format": "png", "captureBeyondViewport": True},
            )
            data = base64.b64decode(res["data"])
            with open(out_path, "wb") as f:
                f.write(data)
            print(f"ok {out_path} {len(data)} bytes")
    finally:
        # Reset the persistent tab so the next caller starts clean.
        try:
            async with websockets.connect(ws_url) as ws:
                await cdp_call(ws, 99, "Page.navigate", {"url": "about:blank"})
        except Exception:
            pass


def main() -> None:
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    url = sys.argv[1]
    out = sys.argv[2]
    auth = sys.argv[3] if len(sys.argv) > 3 else None
    cookie = sys.argv[4] if len(sys.argv) > 4 else None
    asyncio.run(shoot(url, out, auth, extra_cookie=cookie))


if __name__ == "__main__":
    main()
