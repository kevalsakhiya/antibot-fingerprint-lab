"""
Full-browser client with Playwright — the heaviest, most evasion-complete
layer. A real Chromium gives you a genuine TLS stack, genuine HTTP/2 ordering,
real client-hint headers and a real JS/canvas/WebGL surface. The remaining
tells are automation flags (navigator.webdriver, CDP artefacts, headless
quirks), which this script patches.

Requires:  pip install playwright && playwright install chromium

    python -m detector.server http
    python clients/browser_playwright.py http://127.0.0.1:8899/scrape-me
"""
from __future__ import annotations

import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8899/scrape-me"

# Minimal stealth: hide the two loudest automation tells before any page JS runs.
STEALTH_JS = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
window.chrome = window.chrome || { runtime: {} };
Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
"""


def main():
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("playwright not installed. Run:")
        print("  pip install playwright && playwright install chromium")
        return

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            locale="en-US",
        )
        ctx.add_init_script(STEALTH_JS)
        page = ctx.new_page()
        resp = page.goto(TARGET, wait_until="domcontentloaded")
        print("status:", resp.status if resp else "n/a")
        print(page.content()[:1500])
        browser.close()

    print()
    print("A real browser passes header-order and client-hint checks for free;")
    print("the init-script removes navigator.webdriver and friends so the JS")
    print("fingerprint (web/fingerprint.html) also comes back clean.")


if __name__ == "__main__":
    main()
