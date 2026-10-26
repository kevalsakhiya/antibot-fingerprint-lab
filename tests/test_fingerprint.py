"""
Self-contained tests — no network, no third-party deps. They generate a real
ClientHello from the local TLS stack and assert the parsers behave.

    python -m pytest tests/ -q        # if pytest is installed
    python tests/test_fingerprint.py   # plain-python fallback runner
"""
from __future__ import annotations

import os
import ssl
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fingerprint.ja3 import parse_client_hello, _is_grease  # noqa: E402
from fingerprint.http2 import build as build_http2  # noqa: E402
from fingerprint.headers import analyze  # noqa: E402


def _real_client_hello() -> bytes:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname="example.com")
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


def test_grease_detection():
    for g in (0x0A0A, 0x1A1A, 0x2A2A, 0xFAFA, 0xDADA):
        assert _is_grease(g), f"{g:#x} should be GREASE"
    for not_g in (0x1301, 0x0035, 0xC02F, 0x0A0B, 0x0B0A):
        assert not _is_grease(not_g), f"{not_g:#x} should NOT be GREASE"


def test_ja3_parses_real_client_hello():
    fp = parse_client_hello(_real_client_hello())
    assert fp.server_name == "example.com"
    assert len(fp.ciphers) > 0
    assert 0x000A in fp.extensions or len(fp.extensions) > 0
    assert len(fp.ja3) == 32
    assert all(c in "0123456789abcdef" for c in fp.ja3)
    assert fp.ja3_string.count(",") == 4  # five JA3 fields


def test_ja3_is_deterministic():
    raw = _real_client_hello()
    assert parse_client_hello(raw).ja3 == parse_client_hello(raw).ja3


def test_ja3_strips_grease():
    fp = parse_client_hello(_real_client_hello())
    assert not any(_is_grease(c) for c in fp.ciphers)
    assert not any(_is_grease(e) for e in fp.extensions)


def test_http2_akamai_string():
    fp = build_http2(
        settings=[(1, 65536), (2, 0), (4, 6291456), (6, 262144)],
        window_update=15663105,
        priorities=[],
        pseudo_header_order=["m", "a", "s", "p"],
    )
    assert fp.akamai_string == "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p"
    assert len(fp.akamai_hash) == 32


def test_headers_flags_fake_chrome():
    v = analyze([
        ("User-Agent", "Mozilla/5.0 Chrome/120.0 Safari/537.36"),
        ("Accept-Encoding", "gzip, deflate"),
        ("Accept", "*/*"),
    ])
    assert v.ua_claims_chrome is True
    assert v.consistent is False
    assert "sec-ch-ua" in v.missing_browser_headers


def test_headers_accepts_real_chrome_order():
    from fingerprint.headers import CHROME_ORDER
    v = analyze([(h, "x") for h in CHROME_ORDER])
    assert v.order_similarity >= 0.9
    assert v.consistent is True


def _run_all():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for t in tests:
        t()
        print(f"  ok  {t.__name__}")
        passed += 1
    print(f"\n{passed}/{len(tests)} tests passed")


if __name__ == "__main__":
    _run_all()
