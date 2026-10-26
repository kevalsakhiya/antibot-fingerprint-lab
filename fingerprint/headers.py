"""
HTTP header-order and consistency analysis.

The *order* of HTTP request headers is remarkably stable per client and rarely
controllable from high-level HTTP libraries. Real Chrome sends a fixed order
(Host, Connection, sec-ch-ua, ..., User-Agent, Accept, ...); `requests`/urllib3
send a different, alphabetically-ish order and omit the `sec-ch-*` client
hints entirely. Combined with UA-vs-fingerprint consistency checks, header
order is a strong, cheap bot signal.

This module scores a request's headers for:
  1. header ORDER vs a known-browser template (edit distance of positions)
  2. presence of browser-only headers (sec-ch-ua, sec-fetch-*)
  3. UA/fingerprint CONSISTENCY (UA claims Chrome but no client hints, etc.)
"""
from __future__ import annotations

from dataclasses import dataclass

# A representative Chrome desktop header order (lower-cased).
CHROME_ORDER = [
    "host", "connection", "cache-control", "sec-ch-ua",
    "sec-ch-ua-mobile", "sec-ch-ua-platform", "upgrade-insecure-requests",
    "user-agent", "accept", "sec-fetch-site", "sec-fetch-mode",
    "sec-fetch-user", "sec-fetch-dest", "accept-encoding", "accept-language",
]

BROWSER_ONLY = [
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest",
]


@dataclass
class HeaderVerdict:
    order_similarity: float   # 0..1, 1 = identical ordering to Chrome template
    missing_browser_headers: list[str]
    ua_claims_chrome: bool
    consistent: bool
    notes: list[str]


def _order_similarity(order: list[str], template: list[str]) -> float:
    """Fraction of template headers that appear in the same relative order."""
    present = [h for h in template if h in order]
    if len(present) < 2:
        return 0.0
    idx = [order.index(h) for h in present]
    in_order = sum(1 for a, b in zip(idx, idx[1:]) if a < b)
    return in_order / (len(idx) - 1)


def analyze(headers: list[tuple[str, str]]) -> HeaderVerdict:
    """`headers` is an ordered list of (name, value) as received on the wire."""
    names = [h.lower() for h, _ in headers]
    hdr_map = {h.lower(): v for h, v in headers}

    sim = _order_similarity(names, CHROME_ORDER)
    missing = [h for h in BROWSER_ONLY if h not in names]

    ua = hdr_map.get("user-agent", "")
    claims_chrome = "chrome" in ua.lower() and "edg" not in ua.lower()

    notes: list[str] = []
    consistent = True

    if claims_chrome and missing:
        consistent = False
        notes.append(
            f"UA claims Chrome but {len(missing)} browser-only header(s) absent: "
            f"{', '.join(missing)}"
        )
    if claims_chrome and sim < 0.6:
        consistent = False
        notes.append(f"UA claims Chrome but header order is unlike Chrome (sim={sim:.2f})")
    if not names:
        notes.append("no headers supplied")

    return HeaderVerdict(
        order_similarity=round(sim, 3),
        missing_browser_headers=missing,
        ua_claims_chrome=claims_chrome,
        consistent=consistent,
        notes=notes,
    )


if __name__ == "__main__":
    print("== python-requests style ==")
    v = analyze([
        ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"),
        ("Accept-Encoding", "gzip, deflate"),
        ("Accept", "*/*"),
        ("Connection", "keep-alive"),
    ])
    print(v)
    print()
    print("== real-Chrome style ==")
    v = analyze([(h, "x") for h in CHROME_ORDER])
    print(v)
