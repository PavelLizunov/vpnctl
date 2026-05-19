#!/usr/bin/env python3
"""Layout-audit helper — drives headless Chrome over CDP to ASSERT
bounding-box invariants on the rendered admin pages.

WHY THIS EXISTS
---------------
`scripts/visual_check.py` captures a PNG. PNGs catch «I can see it's
wrong» bugs only when a human reads the screenshot. The 2026-05-19
QR-jump bug bounced through TWO «fixed it» cycles because the human
loop is slow + fallible:

  1. I wrote `> svg` in inline CSS; Maud HTML-escaped `>` to `&gt;`;
     the selector silently matched nothing → QRs stayed jumpy. The
     PNG-only check made me think it was fixed.
  2. Even after the selector worked, the row-height drift between
     Flow A/B/C survived because OUTER row height ≠ QR card height.
     Again invisible until Pavel screenshotted it.

This script complements `visual_check.py` with PROGRAMMATIC layout
assertions — query the browser's computed bounding boxes for a list
of CSS selectors and check invariants (same width / same height /
same Y / no overflow). Failure prints offending boxes so the fix
is direct, not a scavenger hunt.

USAGE
-----
    python3 scripts/layout_check.py <url> [user:pass] [cookie]

    # exits non-zero if any check fails — wire into CI as the
    # «layer 6.5» gate (DOM smoke + visual PNG + layout audit).

The checks live in CHECKS (bottom of file) — selector + invariant
+ description per row. Add a row, re-run, done.

REQUIREMENTS
------------
Same Chrome instance as visual_check.py (homelab CDP at
http://192.168.0.142:9222). Python deps: websockets ≥ 12.

NOTES ON METHODOLOGY
--------------------
- This is NOT a pixel-diff tool. Pixel-diffs (BackstopJS, Lost
  Pixel, reg-suit, Percy) work by snapshotting a baseline and
  failing on any pixel delta — high false-positive rate (fonts,
  anti-aliasing, scrollbar widths drift between Chrome versions).
- This is an ASSERTION tool. You declare «all .vpnctl-qr-frame
  elements have width within 1 px of each other» and the tool
  enforces it. Stable across browser updates, font swaps, dark-mode
  recolors. The output tells you the exact offending dimensions
  when an assertion fires.
- For pixel-diff coverage we deliberately still rely on the manual
  PNG step (Pavel screenshots → me reads). Pixel-diff would
  require a baseline-storage workflow we don't want to maintain.
"""

from __future__ import annotations

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


# JS that returns an array of {selector, count, boxes:[{x,y,w,h}…]}.
# Runs in the page; uses native `getBoundingClientRect()` for accurate
# post-CSS dimensions (handles `min-height`, transforms, scrollbars).
QUERY_JS = """
(() => {
  const out = [];
  for (const sel of SELECTORS) {
    const els = Array.from(document.querySelectorAll(sel));
    out.push({
      selector: sel,
      count: els.length,
      boxes: els.map(el => {
        const r = el.getBoundingClientRect();
        return {
          x: Math.round(r.x),
          y: Math.round(r.y),
          w: Math.round(r.width),
          h: Math.round(r.height),
        };
      }),
    });
  }
  return out;
})()
"""


async def query_boxes(
    url: str,
    selectors: list[str],
    basic_auth: str | None,
    viewport: tuple[int, int] = (1400, 1800),
    extra_cookie: str | None = None,
) -> list[dict]:
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
            # Tiny settle for font swap + layout shift.
            await asyncio.sleep(0.6)
            sel_literal = json.dumps(selectors)
            expr = "const SELECTORS = " + sel_literal + "; " + QUERY_JS
            res = await cdp_call(
                ws,
                8,
                "Runtime.evaluate",
                {"expression": expr, "returnByValue": True},
            )
            return res.get("result", {}).get("value", [])
    finally:
        try:
            async with websockets.connect(ws_url) as ws:
                await cdp_call(ws, 99, "Page.navigate", {"url": "about:blank"})
        except Exception:  # noqa: BLE001
            pass


# ── Assertions ──────────────────────────────────────────────────────


def all_equal_width(boxes: list[dict], tolerance_px: int = 1) -> tuple[bool, str]:
    """All boxes within `tolerance_px` of each other on width."""
    if len(boxes) < 2:
        return True, "trivially true (<2 boxes)"
    widths = [b["w"] for b in boxes]
    span = max(widths) - min(widths)
    if span <= tolerance_px:
        return True, f"all widths within {span}px (max tol {tolerance_px}px)"
    return False, f"width spread = {span}px > tol {tolerance_px}px; widths={widths}"


def all_equal_height(boxes: list[dict], tolerance_px: int = 1) -> tuple[bool, str]:
    """All boxes within `tolerance_px` of each other on height."""
    if len(boxes) < 2:
        return True, "trivially true (<2 boxes)"
    heights = [b["h"] for b in boxes]
    span = max(heights) - min(heights)
    if span <= tolerance_px:
        return True, f"all heights within {span}px (max tol {tolerance_px}px)"
    return False, f"height spread = {span}px > tol {tolerance_px}px; heights={heights}"


def all_start_at_same_y(boxes: list[dict], tolerance_px: int = 2) -> tuple[bool, str]:
    """All boxes start at the same Y coordinate (top-aligned)."""
    if len(boxes) < 2:
        return True, "trivially true (<2 boxes)"
    ys = [b["y"] for b in boxes]
    span = max(ys) - min(ys)
    if span <= tolerance_px:
        return True, f"all Y within {span}px"
    return False, f"Y spread = {span}px > tol {tolerance_px}px; ys={ys}"


def at_least_one(boxes: list[dict], _tolerance_px: int = 0) -> tuple[bool, str]:
    """The selector matched at least one element on the page."""
    if boxes:
        return True, f"{len(boxes)} match(es)"
    return False, "selector matched nothing — element may have been removed"


# ── Check definitions ──────────────────────────────────────────────
#
# Each row: (path on prod, [(selector, assertion_fn, tol_px, msg), ...]).
# Add a new (URL, checks) pair when you add a new page that needs
# layout guarantees.

CHECKS: list[tuple[str, list[tuple[str, callable, int, str]]]] = [
    (
        # User-detail with QRs + cross-nav links. Pin the Flow A/B/C/D
        # column-alignment bug Pavel screenshotted twice.
        "/admin/users/brat",
        [
            (
                ".vpnctl-qr-frame",
                all_equal_width,
                1,
                "QR frames must be the same width across all flows",
            ),
            (
                ".vpnctl-qr-frame",
                all_equal_height,
                1,
                "QR frames must be the same height across all flows",
            ),
        ],
    ),
    (
        # Servers page — sanity check the page renders.
        "/admin/servers",
        [(".ed-art-h1", at_least_one, 0, "servers page H1 must render")],
    ),
]


async def run() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    base = sys.argv[1].rstrip("/")
    auth = sys.argv[2] if len(sys.argv) > 2 else None
    cookie = sys.argv[3] if len(sys.argv) > 3 else None

    failures = 0
    for path, checks in CHECKS:
        url = base + path
        selectors = list({sel for (sel, _, _, _) in checks})
        try:
            results = await query_boxes(url, selectors, auth, extra_cookie=cookie)
        except Exception as e:  # noqa: BLE001
            print(f"FAIL {path} — could not query: {e}")
            failures += 1
            continue
        by_sel = {r["selector"]: r["boxes"] for r in results}
        for sel, fn, tol, msg in checks:
            boxes = by_sel.get(sel, [])
            ok, detail = fn(boxes, tol)
            marker = "ok  " if ok else "FAIL"
            print(f"{marker} {path}  {sel:32s}  {fn.__name__:20s}  {detail}")
            if not ok:
                print(f"     ↳ {msg}")
                failures += 1
    print()
    if failures:
        print(f"{failures} layout assertion(s) failed.")
        return 1
    print("all layout assertions passed.")
    return 0


def main() -> None:
    sys.exit(asyncio.run(run()))


if __name__ == "__main__":
    main()
