"""Content-Transfer-Encoding decoders with corruption detection."""

from __future__ import annotations

import base64
import binascii
import re

from .errors import TransferEncodingError

_B64_ALPHABET = re.compile(rb"^[A-Za-z0-9+/]*={0,2}$")
_WS = re.compile(rb"\s+")
_HEX = set(b"0123456789abcdefABCDEF")


def decode_base64(data: bytes) -> bytes:
    """Strictly decode Base64, rejecting illegal characters and truncation."""
    compact = _WS.sub(b"", data)
    if not _B64_ALPHABET.match(compact):
        raise TransferEncodingError("base64 payload contains illegal characters")
    if b"=" in compact[:-2]:
        raise TransferEncodingError("base64 padding appears before end of data")
    if len(compact) % 4 != 0:
        raise TransferEncodingError(
            f"base64 payload is truncated: length {len(compact)} is not a multiple of 4"
        )
    try:
        return base64.b64decode(compact, validate=True)
    except binascii.Error as exc:
        raise TransferEncodingError(f"invalid base64 payload: {exc}") from exc


def decode_quoted_printable(data: bytes) -> bytes:
    """Decode quoted-printable, rejecting malformed ``=XX`` escapes."""
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        byte = data[i]
        if byte != 0x3D:  # '='
            out.append(byte)
            i += 1
            continue
        rest = data[i + 1 : i + 3]
        if rest[:1] == b"\n":  # soft line break: "=\n"
            i += 2
        elif rest[:2] == b"\r\n":  # soft line break: "=\r\n"
            i += 3
        elif len(rest) >= 2 and rest[0] in _HEX and rest[1] in _HEX:
            out.append(int(rest[:2], 16))
            i += 3
        elif i + 1 == n:
            raise TransferEncodingError(
                "quoted-printable payload is truncated: dangling '=' at end of data"
            )
        else:
            raise TransferEncodingError(
                f"invalid quoted-printable escape at offset {i}: "
                f"'={data[i + 1:i + 3].decode('latin-1')}'"
            )
    return bytes(out)


def decode_transfer(data: bytes, encoding: str) -> bytes:
    """Decode a body according to its Content-Transfer-Encoding."""
    encoding = (encoding or "7bit").strip().lower()
    if encoding in ("7bit", "8bit", "binary", ""):
        return data
    if encoding == "base64":
        return decode_base64(data)
    if encoding == "quoted-printable":
        return decode_quoted_printable(data)
    raise TransferEncodingError(f"unsupported content-transfer-encoding: {encoding!r}")
