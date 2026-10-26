"""
TLS-impersonating client with curl_cffi.

curl_cffi binds to curl-impersonate, which ships BoringSSL builds configured to
reproduce real Chrome/Safari/Firefox ClientHellos byte-for-byte — so the JA3
and HTTP/2 Akamai fingerprints match a genuine browser, not a Python library.
This is the first real layer of evasion: defeat the TLS fingerprint.

Requires:  pip install curl_cffi

Run the TLS sniffer and point this at it to compare JA3 against
clients/vanilla_requests.py:

    python -m detector.server tls
    python clients/impersonate_curlcffi.py https://127.0.0.1:8443/
"""
from __future__ import annotations

import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "https://tls.browserleaks.com/json"


def main():
    try:
        from curl_cffi import requests
    except ImportError:
        print("curl_cffi not installed. Run:  pip install curl_cffi")
        print("(Left out of the default requirements so the repo stays import-clean;")
        print(" it pulls a compiled curl-impersonate binary.)")
        return

    # impersonate= makes the ClientHello + HTTP/2 settings match this browser.
    resp = requests.get(TARGET, impersonate="chrome", verify=False, timeout=10)
    print("status:", resp.status_code)
    body = resp.text
    print(body[:1200])
    print()
    print("Against a JA3-reporting endpoint (e.g. tls.browserleaks.com/json or")
    print("tls.peet.ws/api/all) the reported JA3 now matches real Chrome — the")
    print("exact fingerprint vanilla_requests.py could never produce.")


if __name__ == "__main__":
    main()
