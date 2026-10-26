"""
HTTP/2 fingerprinting (Akamai-style).

Once TLS is negotiated, the *shape* of a client's HTTP/2 connection is itself a
fingerprint. Browsers, Go's net/http, Python httpx and curl each open the
connection with a characteristic SETTINGS frame, window-update size, priority
tree and — crucially — a fixed order of the `:method :authority :scheme :path`
pseudo-headers. Akamai formalised this as:

    akamai_fp = SETTINGS | WINDOW_UPDATE | PRIORITY | PSEUDO_HEADER_ORDER

    e.g.  1:65536;2:0;4:6291456;6:262144 | 15663105 | 0 | m,a,s,p

A real Chrome sends `m,a,s,p`; many HTTP libraries send `m,s,a,p` or omit
priority frames entirely — a cheap, UA-independent bot tell.

This module builds the Akamai string from parsed frames, and includes a
minimal HTTP/2 frame reader so it can run against bytes captured after the
connection preface.

Reference: https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients.pdf
"""
from __future__ import annotations

from dataclasses import dataclass, field

# HTTP/2 frame types (RFC 7540 §6)
FRAME_SETTINGS = 0x4
FRAME_WINDOW_UPDATE = 0x8
FRAME_PRIORITY = 0x2
FRAME_HEADERS = 0x1

CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

_SETTINGS_NAMES = {
    0x1: "HEADER_TABLE_SIZE",
    0x2: "ENABLE_PUSH",
    0x3: "MAX_CONCURRENT_STREAMS",
    0x4: "INITIAL_WINDOW_SIZE",
    0x5: "MAX_FRAME_SIZE",
    0x6: "MAX_HEADER_LIST_SIZE",
}


@dataclass
class Http2Fingerprint:
    settings: list[tuple[int, int]] = field(default_factory=list)
    window_update: int = 0
    priorities: list[tuple[int, int, int, int]] = field(default_factory=list)
    pseudo_header_order: list[str] = field(default_factory=list)

    @property
    def akamai_string(self) -> str:
        s = ";".join(f"{k}:{v}" for k, v in self.settings) or "0"
        wu = str(self.window_update)
        if self.priorities:
            p = ",".join(
                f"{sid}:{excl}:{dep}:{weight}"
                for sid, excl, dep, weight in self.priorities
            )
        else:
            p = "0"
        ph = ",".join(self.pseudo_header_order) or "0"
        return f"{s}|{wu}|{p}|{ph}"

    @property
    def akamai_hash(self) -> str:
        import hashlib
        return hashlib.md5(self.akamai_string.encode()).hexdigest()

    def describe_settings(self) -> list[str]:
        return [f"{_SETTINGS_NAMES.get(k, k)} = {v}" for k, v in self.settings]


def parse_frames(data: bytes) -> Http2Fingerprint:
    """Parse HTTP/2 frames (after the optional connection preface) and build
    the Akamai fingerprint. Pseudo-header order is read from a HEADERS frame if
    the caller has pre-decoded it; raw HPACK decoding is out of scope here, so
    HEADERS pseudo-order is supplied separately via `with_pseudo_order`."""
    if data.startswith(CONNECTION_PREFACE):
        data = data[len(CONNECTION_PREFACE):]

    fp = Http2Fingerprint()
    pos = 0
    n = len(data)
    while pos + 9 <= n:
        length = int.from_bytes(data[pos:pos + 3], "big")
        ftype = data[pos + 3]
        # flags = data[pos + 4]
        stream_id = int.from_bytes(data[pos + 5:pos + 9], "big") & 0x7FFFFFFF
        payload = data[pos + 9:pos + 9 + length]
        pos += 9 + length

        if ftype == FRAME_SETTINGS:
            for i in range(0, len(payload), 6):
                key = int.from_bytes(payload[i:i + 2], "big")
                val = int.from_bytes(payload[i + 2:i + 6], "big")
                fp.settings.append((key, val))
        elif ftype == FRAME_WINDOW_UPDATE:
            fp.window_update = int.from_bytes(payload[0:4], "big") & 0x7FFFFFFF
        elif ftype == FRAME_PRIORITY and len(payload) >= 5:
            dep = int.from_bytes(payload[0:4], "big")
            excl = (dep >> 31) & 1
            dep &= 0x7FFFFFFF
            weight = payload[4]
            fp.priorities.append((stream_id, excl, dep, weight))

    return fp


def build(settings, window_update, priorities, pseudo_header_order) -> Http2Fingerprint:
    """Construct a fingerprint directly from decoded components (useful when a
    proxy/h2 library hands you structured frame data)."""
    return Http2Fingerprint(
        settings=list(settings),
        window_update=window_update,
        priorities=list(priorities),
        pseudo_header_order=list(pseudo_header_order),
    )


# Known reference fingerprints for comparison in the detector.
KNOWN = {
    # Chrome 120+ on desktop (illustrative; verify against your own capture)
    "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p": "Chrome (desktop)",
    "1:4096;2:0;4:65535;5:16384|0|0|m,s,a,p": "generic HTTP/2 library",
}


if __name__ == "__main__":
    # Demonstrate the string format with a Chrome-like component set.
    fp = build(
        settings=[(1, 65536), (2, 0), (4, 6291456), (6, 262144)],
        window_update=15663105,
        priorities=[],
        pseudo_header_order=["m", "a", "s", "p"],
    )
    print("Akamai HTTP/2 fingerprint :", fp.akamai_string)
    print("md5                       :", fp.akamai_hash)
    print("looks like                :", KNOWN.get(fp.akamai_string, "unknown"))
    for line in fp.describe_settings():
        print("  -", line)
