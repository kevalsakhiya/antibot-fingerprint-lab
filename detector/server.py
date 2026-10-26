"""
Controlled detector server — the "target" your scraper tries to pass.

Two modes, both self-contained (localhost only, no external calls):

  python -m detector.server http      # HTTP header/UA detector on :8899
  python -m detector.server tls        # raw TLS ClientHello JA3 sniffer on :8443

HTTP mode scores each request's header order, missing client-hints and UA
consistency, and returns a JSON bot verdict. Point any of the clients/ demos
at it and watch vanilla requests score high while a real browser scores low.

TLS mode listens on a raw socket, reads the ClientHello bytes off the wire
(before completing the handshake), computes JA3, prints it, and closes — the
simplest honest way to show JA3 capture at the socket layer without shipping a
full TLS-terminating proxy.
"""
from __future__ import annotations

import json
import socket
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Allow running as `python -m detector.server` or `python detector/server.py`.
sys.path.insert(0, __file__.rsplit("/detector/", 1)[0])

from fingerprint.headers import analyze  # noqa: E402
from detector.score import score_request  # noqa: E402

HTTP_PORT = 8899
TLS_PORT = 8443


class DetectorHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _handle(self):
        # BaseHTTPRequestHandler preserves on-wire header order in self.headers.
        ordered = list(self.headers.items())
        verdict = analyze(ordered)
        bot = score_request(verdict)

        body = json.dumps({
            "path": self.path,
            "received_header_order": [h for h, _ in ordered],
            "header_analysis": {
                "order_similarity": verdict.order_similarity,
                "missing_browser_headers": verdict.missing_browser_headers,
                "ua_claims_chrome": verdict.ua_claims_chrome,
                "consistent": verdict.consistent,
                "notes": verdict.notes,
            },
            "bot_score": bot.as_dict(),
        }, indent=2).encode()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def log_message(self, *args):
        pass  # keep stdout clean for the JSON demo


def run_http():
    srv = ThreadingHTTPServer(("127.0.0.1", HTTP_PORT), DetectorHandler)
    print(f"[http] detector on http://127.0.0.1:{HTTP_PORT}  (Ctrl-C to stop)")
    srv.serve_forever()


def run_tls():
    from fingerprint.ja3 import parse_client_hello
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", TLS_PORT))
    s.listen(5)
    print(f"[tls] JA3 sniffer on 127.0.0.1:{TLS_PORT}  (Ctrl-C to stop)")
    print(f"      try:  curl -sk https://127.0.0.1:{TLS_PORT}/   (handshake will fail — that's fine)")
    while True:
        conn, addr = s.accept()
        try:
            conn.settimeout(2.0)
            data = conn.recv(4096)
            if data:
                try:
                    fp = parse_client_hello(data)
                    print(f"[tls] {addr[0]}:{addr[1]}  SNI={fp.server_name}  "
                          f"ciphers={len(fp.ciphers)}  JA3={fp.ja3}")
                    print(f"      ja3_string={fp.ja3_string}")
                except Exception as e:  # noqa: BLE001
                    print(f"[tls] {addr[0]}:{addr[1]}  not a parseable ClientHello: {e}")
        finally:
            conn.close()


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "http"
    if mode == "tls":
        run_tls()
    else:
        run_http()
