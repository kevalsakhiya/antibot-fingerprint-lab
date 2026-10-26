"""
Bot-likelihood scoring: combine the independent fingerprint signals into a
single 0-100 score with human-readable reasons.

The point of a reverse-engineering portfolio is to show you understand *both*
sides: this is the defender's logic, which is exactly what you have to defeat
when you build a resilient scraper. Each signal is independent, so an evader
has to get *all* of them right at once — which is why naive `requests` +
spoofed User-Agent gets caught instantly, and why TLS-impersonating clients
(curl_cffi, tls-client, uTLS) exist.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from fingerprint.headers import HeaderVerdict


@dataclass
class Signal:
    name: str
    weight: int           # contribution to the bot score if it fires
    fired: bool
    detail: str


@dataclass
class BotScore:
    score: int                       # 0 (human) .. 100 (certain bot)
    verdict: str
    signals: list[Signal] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "verdict": self.verdict,
            "signals": [
                {"name": s.name, "weight": s.weight, "fired": s.fired, "detail": s.detail}
                for s in self.signals
            ],
        }


def score_request(
    header_verdict: HeaderVerdict,
    ja3_known_browser: bool | None = None,
    http2_known_browser: bool | None = None,
) -> BotScore:
    """Combine signals. `ja3_known_browser` / `http2_known_browser` are
    tri-state: True (matches a real browser), False (does not), None (not
    captured for this request)."""
    signals: list[Signal] = []

    # --- header order / browser-header signals ---
    if header_verdict.missing_browser_headers and header_verdict.ua_claims_chrome:
        signals.append(Signal(
            "missing_client_hints", 35, True,
            f"UA claims Chrome but lacks {len(header_verdict.missing_browser_headers)} "
            f"sec-ch/sec-fetch header(s)",
        ))
    else:
        signals.append(Signal("missing_client_hints", 35, False, "client-hint headers present or UA not Chrome"))

    low_order = header_verdict.order_similarity < 0.6 and header_verdict.ua_claims_chrome
    signals.append(Signal(
        "header_order", 20, low_order,
        f"header order similarity to Chrome = {header_verdict.order_similarity}",
    ))

    # --- TLS JA3 ---
    if ja3_known_browser is False:
        signals.append(Signal("ja3_mismatch", 30, True, "JA3 does not match any known browser build"))
    elif ja3_known_browser is True:
        signals.append(Signal("ja3_mismatch", 30, False, "JA3 matches a known browser"))
    else:
        signals.append(Signal("ja3_mismatch", 30, False, "JA3 not captured for this request"))

    # --- HTTP/2 Akamai ---
    if http2_known_browser is False:
        signals.append(Signal("http2_mismatch", 15, True, "HTTP/2 Akamai fingerprint unlike a browser"))
    elif http2_known_browser is True:
        signals.append(Signal("http2_mismatch", 15, False, "HTTP/2 fingerprint matches a browser"))
    else:
        signals.append(Signal("http2_mismatch", 15, False, "HTTP/2 fingerprint not captured"))

    total = sum(s.weight for s in signals if s.fired)
    total = max(0, min(100, total))
    if total >= 60:
        verdict = "bot"
    elif total >= 30:
        verdict = "suspicious"
    else:
        verdict = "likely-human"

    return BotScore(score=total, verdict=verdict, signals=signals)
