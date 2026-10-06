"""Strict content-transfer-encoding decoders (Base64, quoted-printable)."""

from __future__ import annotations

import base64
import binascii
import re

from .errors import TransferEncodingError

_WS = re.compile(rb"\s+")
_QP_ESCAPE = re.compile(rb"=([0-9A-Fa-f]{2})")


def decode_base64(data: bytes) -> bytes:
    """Decode Base64 strictly: reject illegal chars, bad padding, truncation."""
    compact = _WS.sub(b"", data)
    if re.search(rb"[^A-Za-z0-9+/=]", compact):
        raise TransferEncodingError("base64 payload contains illegal characters")
    if b"=" in compact.rstrip(b"="):
        raise TransferEncodingError("base64 padding appears before end of data")
    if len(compact.rstrip(b"=")) % 4 == 1:
        raise TransferEncodingError("base64 payload is truncated")
    try:
        return base64.b64decode(compact, validate=True)
    except binascii.Error as exc:
        raise TransferEncodingError(f"invalid base64 payload: {exc}") from exc


def decode_quoted_printable(data: bytes) -> bytes:
    """Decode quoted-printable strictly: reject bad escapes and truncation."""
    if data.rstrip(b"\r\n").endswith(b"="):
        raise TransferEncodingError("quoted-printable payload ends with a dangling '='")
    out = bytearray()
    pos = 0
    for match in re.finditer(rb"=", data):
        nxt = data[match.start() + 1: match.start() + 3]
        if _QP_ESCAPE.fullmatch(b"=" + nxt[:2]):
            continue
        if nxt.startswith(b"\r\n") or nxt.startswith(b"\n"):
            continue  # soft line break
        raise TransferEncodingError(
            f"invalid quoted-printable escape at offset {match.start()}"
        )
    while pos < len(data):
        if data[pos:pos + 1] == b"=":
            esc = data[pos + 1: pos + 3]
            if _QP_ESCAPE.fullmatch(b"=" + esc[:2]):
                out.append(int(esc[:2], 16))
                pos += 3
                continue
            if data[pos + 1:pos + 3] == b"\r\n":
                pos += 3
                continue
            if data[pos + 1:pos + 2] == b"\n":
                pos += 2
                continue
        out.append(data[pos])
        pos += 1
    return bytes(out)


def decode_transfer(data: bytes, encoding: str | None) -> bytes:
    """Dispatch on Content-Transfer-Encoding; unknown encodings pass through."""
    enc = (encoding or "7bit").strip().lower()
    if enc in ("7bit", "8bit", "binary", ""):
        return data
    if enc == "base64":
        return decode_base64(data)
    if enc in ("quoted-printable", "quopri"):
        return decode_quoted_printable(data)
    return data  # unknown encodings are kept raw rather than guessed
