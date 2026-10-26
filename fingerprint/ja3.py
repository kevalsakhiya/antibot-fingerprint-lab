"""
JA3 / JA3S TLS fingerprinting — pure-Python ClientHello parser.

JA3 fingerprints a TLS client by the *shape* of its ClientHello: the exact
set and order of cipher suites, extensions, elliptic curves and EC point
formats it advertises. Two clients using the same OpenSSL/BoringSSL build
produce the same JA3; a Python `requests` call and real Chrome produce very
different ones. Anti-bot systems key on this because it is set at the TLS
layer, *below* anything a User-Agent header can lie about.

    JA3 string = SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats
    JA3 hash   = md5(JA3 string)

GREASE values (RFC 8701) are stripped before hashing, exactly as the original
Salesforce JA3 implementation does — otherwise Chrome's randomised GREASE would
change the fingerprint on every connection.

This module parses the raw bytes itself (no pyOpenSSL/scapy dependency) so it
can run against a captured ClientHello, a pcap, or bytes read straight off a
socket in `detector/server.py`.

References:
  - JA3: https://github.com/salesforce/ja3
  - GREASE: RFC 8701
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field


def _is_grease(value: int) -> bool:
    """RFC 8701 GREASE values: 0x0a0a, 0x1a1a, ... 0xfafa (both bytes equal,
    low nibble == 0xa)."""
    hi, lo = (value >> 8) & 0xFF, value & 0xFF
    return hi == lo and (lo & 0x0F) == 0x0A


class _Reader:
    """Minimal big-endian byte reader with bounds checking."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def _need(self, n: int) -> None:
        if self.pos + n > len(self.data):
            raise ValueError(
                f"truncated TLS message: wanted {n} bytes at offset {self.pos}, "
                f"only {len(self.data) - self.pos} remain"
            )

    def u8(self) -> int:
        self._need(1)
        v = self.data[self.pos]
        self.pos += 1
        return v

    def u16(self) -> int:
        self._need(2)
        v = int.from_bytes(self.data[self.pos:self.pos + 2], "big")
        self.pos += 2
        return v

    def u24(self) -> int:
        self._need(3)
        v = int.from_bytes(self.data[self.pos:self.pos + 3], "big")
        self.pos += 3
        return v

    def take(self, n: int) -> bytes:
        self._need(n)
        v = self.data[self.pos:self.pos + n]
        self.pos += n
        return v


# TLS extension type numbers we decode for the JA3 curve/point-format fields.
_EXT_SUPPORTED_GROUPS = 0x000A   # elliptic curves
_EXT_EC_POINT_FORMATS = 0x000B


@dataclass
class ClientHelloFingerprint:
    tls_version: int
    ciphers: list[int] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)
    curves: list[int] = field(default_factory=list)
    point_formats: list[int] = field(default_factory=list)
    server_name: str | None = None

    @property
    def ja3_string(self) -> str:
        parts = [
            str(self.tls_version),
            "-".join(str(c) for c in self.ciphers),
            "-".join(str(e) for e in self.extensions),
            "-".join(str(c) for c in self.curves),
            "-".join(str(p) for p in self.point_formats),
        ]
        return ",".join(parts)

    @property
    def ja3(self) -> str:
        return hashlib.md5(self.ja3_string.encode()).hexdigest()


def _maybe_unwrap_record(data: bytes) -> bytes:
    """Accept either a raw TLS record (starts with 0x16 handshake content
    type) or a bare handshake message (starts with 0x01 ClientHello). Returns
    the handshake bytes."""
    if not data:
        raise ValueError("empty input")
    if data[0] == 0x16:  # TLS record, content type = handshake
        r = _Reader(data)
        r.u8()            # content type
        r.u16()           # record version
        rec_len = r.u16()
        return r.take(rec_len)
    return data  # assume already a handshake message


def parse_client_hello(data: bytes) -> ClientHelloFingerprint:
    """Parse a ClientHello (raw record or bare handshake) into its JA3 fields."""
    handshake = _maybe_unwrap_record(data)
    r = _Reader(handshake)

    msg_type = r.u8()
    if msg_type != 0x01:
        raise ValueError(f"not a ClientHello (handshake type {msg_type:#x})")
    r.u24()                       # handshake length
    tls_version = r.u16()         # legacy_version (TLS 1.3 hides real ver in ext)
    r.take(32)                    # random
    r.take(r.u8())                # session id

    cipher_bytes = r.take(r.u16())
    ciphers = [
        int.from_bytes(cipher_bytes[i:i + 2], "big")
        for i in range(0, len(cipher_bytes), 2)
    ]
    ciphers = [c for c in ciphers if not _is_grease(c)]

    r.take(r.u8())                # compression methods

    extensions: list[int] = []
    curves: list[int] = []
    point_formats: list[int] = []
    server_name: str | None = None

    # Extensions block is optional in the wire format.
    if r.pos < len(handshake):
        ext_total = r.u16()
        end = r.pos + ext_total
        while r.pos < end:
            ext_type = r.u16()
            ext_len = r.u16()
            body = r.take(ext_len)
            if not _is_grease(ext_type):
                extensions.append(ext_type)

            if ext_type == _EXT_SUPPORTED_GROUPS:
                er = _Reader(body)
                glen = er.u16()
                g = er.take(glen)
                curves = [
                    int.from_bytes(g[i:i + 2], "big")
                    for i in range(0, len(g), 2)
                ]
                curves = [c for c in curves if not _is_grease(c)]
            elif ext_type == _EXT_EC_POINT_FORMATS:
                er = _Reader(body)
                plen = er.u8()
                point_formats = list(er.take(plen))
            elif ext_type == 0x0000:  # server_name
                try:
                    er = _Reader(body)
                    er.u16()          # server name list length
                    er.u8()           # name type (0 = host_name)
                    name_len = er.u16()
                    server_name = er.take(name_len).decode("ascii", "replace")
                except ValueError:
                    pass

    return ClientHelloFingerprint(
        tls_version=tls_version,
        ciphers=ciphers,
        extensions=extensions,
        curves=curves,
        point_formats=point_formats,
        server_name=server_name,
    )


def ja3_from_bytes(data: bytes) -> tuple[str, str]:
    """Convenience: return (ja3_string, ja3_md5) for a ClientHello."""
    fp = parse_client_hello(data)
    return fp.ja3_string, fp.ja3


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        raw = bytes.fromhex(sys.argv[1].strip())
    else:
        # Generate a real ClientHello from the local TLS stack and fingerprint it.
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
        obj = ctx.wrap_bio(inc, out, server_hostname="example.com")
        try:
            obj.do_handshake()
        except ssl.SSLWantReadError:
            pass
        raw = out.read()

    fp = parse_client_hello(raw)
    print("TLS version  :", hex(fp.tls_version))
    print("SNI          :", fp.server_name)
    print("ciphers      :", len(fp.ciphers))
    print("extensions   :", fp.extensions)
    print("JA3 string   :", fp.ja3_string)
    print("JA3 (md5)    :", fp.ja3)
