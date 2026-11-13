# Anti-Bot Fingerprint Lab

**A hands-on look at how websites tell real browsers apart from bots — and how scrapers slip past those checks.**

![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
![Tests 7/7](https://img.shields.io/badge/tests-7%2F7%20passing-brightgreen)
![License MIT](https://img.shields.io/badge/license-MIT-black)

---

## What does this repo do?

When you try to scrape a big website, it often blocks you **before you even
get the page** — even if your code sets a perfect "I am Chrome" label. How?
The website looks at dozens of tiny technical fingerprints that a real browser
leaves behind and a script usually doesn't.

This repo **builds that bot-detector from scratch, in plain Python**, so you can
see exactly what those fingerprints are — and then shows the three ways a
scraper defeats them, one layer at a time.

Think of it as a lock and a set of keys, in the same box:
- the **lock** (`detector/`) is a mini version of what Cloudflare / DataDome do,
- the **keys** (`clients/`) are three scrapers, from "gets caught instantly" to
  "looks exactly like a real person."

Everything here runs locally and has **no setup** — the core needs nothing but
Python. It's a learning tool and a portfolio piece, not a service.

---

## The problem, in one example

You write a scraper and set the `User-Agent` header to Chrome's. You'd think the
site now believes you're Chrome. It doesn't. Run the demo in this repo and the
detector flags your scraper anyway:

```
Bot verdict : suspicious (score 55/100)
  ⚠ UA claims Chrome but is missing 6 of Chrome's normal headers
  ⚠ the ORDER of your headers doesn't match Chrome's
```

The label said "Chrome," but the fingerprint underneath didn't. **That gap is
what this repo is about** — and closing it is the real skill in large-scale
scraping.

---

## The four things a website checks

A bot-detector scores you on signals that live *underneath* the headers you can
easily fake. This repo implements all four as readable Python:

| # | Check | In plain terms | Code |
|---|-------|----------------|------|
| 1 | **TLS / JA3** | The way your code opens the secure (https) connection has a "handshake signature." Chrome's and Python's are different. | [`fingerprint/ja3.py`](fingerprint/ja3.py) |
| 2 | **HTTP/2** | The low-level settings your client sends when it starts talking. Browsers and code libraries send different ones. | [`fingerprint/http2.py`](fingerprint/http2.py) |
| 3 | **Headers** | The *order* of your request headers, and whether you include the extra ones (`sec-ch-ua`, `sec-fetch-*`) that only real browsers send. | [`fingerprint/headers.py`](fingerprint/headers.py) |
| 4 | **Browser / JavaScript** | Signals the page reads from inside the browser: is `navigator.webdriver` on? is the graphics card real or fake? | [`web/fingerprint.html`](web/fingerprint.html) |

The detector ([`detector/`](detector/)) adds these up into one **0–100 bot
score**. Because the four checks are independent, a scraper has to pass **all of
them at once** — which is why faking just the `User-Agent` never works.

---

## Quickstart

No installation needed for the core — just Python 3.11+.

```bash
# 1. Fingerprint a real secure-connection handshake from your own machine
python fingerprint/ja3.py

# 2. Run the tests (they create a real handshake and check the parser)
python tests/test_fingerprint.py

# 3. See the live detector catch a naive scraper
python -m detector.server http       # terminal 1: start the detector
python clients/vanilla_requests.py    # terminal 2: scrape it, watch it get flagged
```

---

## See it in action

**Fingerprinting a real handshake** (`python fingerprint/ja3.py`):

```
SNI        : example.com
ciphers    : 17
JA3 string : 771,4866-4867-4865-49196-...,65281-0-11-10-35-22-23-13-43-45-51,...,0
JA3 (md5)  : f21f8e6cf70d5980ecfe9fa2e0ef401c
```

That `JA3 (md5)` is the connection's "signature." A real Chrome produces a
specific one; Python produces a different one — and detectors keep lists of both.

**A naive scraper hitting the detector** (`python clients/vanilla_requests.py`):

```
Header order the server saw : ['Accept-Encoding', 'Host', 'User-Agent', 'Connection']
Bot verdict                 : suspicious (score 55/100)
```

It set a flawless Chrome `User-Agent` — and still scored 55/100, because the
header order and missing client-hint headers gave it away.

---

## The three scrapers (the evasion ladder)

The `clients/` folder has three scrapers, each one defeating one more check:

| Scraper | TLS handshake | Headers | Browser signals | Result |
|---------|:-------------:|:-------:|:---------------:|--------|
| `vanilla_requests.py` (plain Python) | ❌ looks like Python | ❌ wrong | — | **caught** |
| `impersonate_curlcffi.py` (TLS impersonation) | ✅ looks like Chrome | ⚠ partly | — | passes the TLS check |
| `browser_playwright.py` (real browser + tweaks) | ✅ real Chrome | ✅ real | ✅ cleaned up | **passes everything** |

The lesson: you don't beat a bot-detector with one clever trick. You climb the
ladder until **every** signal matches a real browser.

---

## What's in here

```
fingerprint/     the detection logic, in plain Python (the heart of the repo)
  ja3.py         reads a TLS handshake and computes its JA3 signature
  http2.py       reads HTTP/2 settings and builds the fingerprint
  headers.py     checks header order and "is this really Chrome?"
detector/        the "target": scores a request and returns a verdict
clients/         the three scrapers, from easy-to-catch to undetectable
web/             a web page that reads the in-browser signals
tests/           quick tests that need no internet and no extra installs
```

## Requirements

The core (parsers, detector, tests) runs on the **Python 3.11+ standard library —
nothing to install.** Two of the scraper demos need an extra package each:

```bash
pip install curl_cffi                                      # for impersonate_curlcffi.py
pip install playwright && playwright install chromium       # for browser_playwright.py
```

They're kept optional so the repo runs anywhere out of the box.

## Scope & honesty

- The JA3 and HTTP/2 algorithms are implemented faithfully. The *example*
  "this is what Chrome looks like" fingerprints are illustrative — they shift
  with each browser version, so check against a live capture
  (e.g. `tls.peet.ws/api/all`) before treating any single value as final.
- The detector is a teaching model of how commercial systems work, not a copy
  of any specific one.
- Everything targets a **local, controlled** endpoint. Only use these techniques
  on systems you're allowed to test.

## About

Built by **Keval Sakhiya** — web-scraping / anti-bot engineer and winner of
[Zyte's Extract Summit](https://www.zyte.com) web-scraping coding competition
(2023). More work: [kevalsakhiya.github.io](https://kevalsakhiya.github.io).

MIT licensed — see [LICENSE](LICENSE).
