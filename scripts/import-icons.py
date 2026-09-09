#!/usr/bin/env python3
"""Reproduce the pinned, local Lucide subset; never needed at runtime."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.request import urlopen
import xml.etree.ElementTree as ET

REV = "a537cb6eb323b885f4c60baf3cec1a995982d167"
BASE = f"https://raw.githubusercontent.com/lucide-icons/lucide/{REV}"
NAMES = """info triangle-alert circle-x check minus equal-not circle circle-dashed
chevron-right chevron-down x arrow-left arrow-right arrow-up arrow-down search
list-filter rotate-cw save activity plus power pause eye eye-off lock-keyhole
lock-keyhole-open key-round trash-2 download upload archive shield-check history
send languages log-out palette calendar layout-dashboard server users bell
settings-2 link unlink scan network shield chart-no-axes-combined code rocket""".split()
ROOT = Path(__file__).resolve().parent.parent


def fetch(path):
    with urlopen(f"{BASE}/{path}", timeout=30) as response:
        return response.read().decode("utf-8")


def symbol(name):
    source = {"trash-2": "trash", "history": "rotate-ccw-clock"}.get(name, name)
    root = ET.fromstring(fetch(f"icons/{source}.svg"))
    allowed = {"path", "circle", "rect", "line", "polyline", "polygon", "ellipse"}
    for node in root.iter():
        node.tag = node.tag.rsplit("}", 1)[-1]
        if node is not root and node.tag not in allowed:
            raise ValueError(f"Unexpected SVG element: {node.tag}")
        if any(key.startswith("on") or key in ("href", "style") for key in node.attrib):
            raise ValueError("Active SVG content is not allowed")
    drawing = "".join(ET.tostring(child, encoding="unicode") for child in root)
    return f'  <symbol id="{name}" viewBox="0 0 24 24">{drawing.strip()}</symbol>'


if __name__ == "__main__":
    with ThreadPoolExecutor(max_workers=8) as pool:
        symbols = list(pool.map(symbol, NAMES))
    license_text = fetch("LICENSE")
    assets = ROOT / "daemon/assets"
    (assets / "icons.svg").write_text(
        f'<!-- Lucide {REV}; see icons-LICENSE.txt. -->\n'
        '<svg xmlns="http://www.w3.org/2000/svg" fill="none" stroke="currentColor" '
        'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">\n'
        + "\n".join(symbols) + "\n</svg>\n", encoding="utf-8")
    (assets / "icons-LICENSE.txt").write_text(license_text, encoding="utf-8")
    print(f"Imported {len(symbols)} local icons from {REV}")
