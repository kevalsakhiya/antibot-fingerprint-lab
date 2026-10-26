"""
Baseline client — a naive scraper. Zero third-party dependencies (stdlib
urllib), so it runs out of the box. Hit the HTTP detector with it and you'll
see it score as a bot: it spoofs a Chrome User-Agent but sends no client-hint
headers and the wrong header order.

    python -m detector.server http        # in one terminal
    python clients/vanilla_requests.py     # in another
"""
from __future__ import annotations

import json
import urllib.request

DETECTOR = "http://127.0.0.1:8899/scrape-me"

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def main():
    # A classic "I set the User-Agent, surely that's enough" scraper.
    req = urllib.request.Request(DETECTOR, headers={"User-Agent": CHROME_UA})
    with urllib.request.urlopen(req, timeout=5) as resp:
        data = json.load(resp)

    print("Header order the server saw :", data["received_header_order"])
    print("Bot verdict                 :", data["bot_score"]["verdict"],
          f"(score {data['bot_score']['score']}/100)")
    for s in data["bot_score"]["signals"]:
        if s["fired"]:
            print(f"  ⚠ {s['name']} (+{s['weight']}) — {s['detail']}")
    print()
    print("Lesson: spoofing the UA string does nothing for header order or the")
    print("missing sec-ch-ua / sec-fetch-* client hints. This is why real")
    print("scrapers need TLS + header + browser impersonation, not just a UA.")


if __name__ == "__main__":
    main()
