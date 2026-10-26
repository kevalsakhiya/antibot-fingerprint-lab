"""Pure-Python client-fingerprinting primitives used by the detector and demos."""
from .ja3 import parse_client_hello, ja3_from_bytes, ClientHelloFingerprint
from .http2 import parse_frames, build as build_http2, Http2Fingerprint
from .headers import analyze as analyze_headers, HeaderVerdict

__all__ = [
    "parse_client_hello",
    "ja3_from_bytes",
    "ClientHelloFingerprint",
    "parse_frames",
    "build_http2",
    "Http2Fingerprint",
    "analyze_headers",
    "HeaderVerdict",
]
