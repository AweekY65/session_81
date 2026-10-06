"""Header unfolding, RFC 2047 encoded-word decoding, parameter parsing."""

from __future__ import annotations

import base64
import binascii
import codecs
import re

from .errors import HeaderError

_ENCODED_WORD = re.compile(r"=\?([^?\s]+)\?([bBqQ])\?([^?]*)\?=")
# Whitespace sitting between two adjacent encoded words must be dropped
# (RFC 2047 section 6.2).
_BETWEEN_WORDS = re.compile(r"(\?=)[ \t]+(=\?)")


def split_head_body(raw: bytes) -> tuple[bytes, bytes]:
    """Split a message/part into its header block and body."""
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            return raw[:idx], raw[idx + len(sep):]
    return raw, b""


def unfold_headers(head: bytes) -> list[tuple[str, str]]:
    """Parse a header block into (name, value) pairs, unfolding continuations.

    Lines beginning with SP/HTAB are folded continuations of the previous
    header. Undecodable bytes are mapped with surrogateescape-tolerant
    latin-1 so nothing is lost before encoded-word decoding.
    """
    text = head.decode("latin-1")
    lines = re.split(r"\r\n|\n", text)
    pairs: list[tuple[str, str]] = []
    for line in lines:
        if not line:
            continue
        if line[0] in " \t":
            if not pairs:
                raise HeaderError("header block starts with a continuation line")
            name, value = pairs[-1]
            pairs[-1] = (name, value + " " + line.strip())
            continue
        name, colon, value = line.partition(":")
        if not colon or not name.strip():
            raise HeaderError(f"malformed header line: {line!r}")
        pairs.append((name.strip(), value.strip()))
    return pairs


def _decode_word(charset: str, encoding: str, payload: str) -> str:
    try:
        if encoding in ("b", "B"):
            data = base64.b64decode(payload, validate=False)
        else:
            # Q-encoding: '_' is a space, '=XX' hex escapes.
            data = re.sub(
                rb"=([0-9A-Fa-f]{2})",
                lambda m: bytes([int(m.group(1), 16)]),
                payload.replace("_", " ").encode("latin-1"),
            )
    except (binascii.Error, ValueError):
        return f"=?{charset}?{encoding}?{payload}?="  # keep raw on damage
    try:
        info = codecs.lookup(charset)
    except LookupError:
        return f"=?{charset}?{encoding}?{payload}?="
    return data.decode(info.name, errors="replace")


def decode_rfc2047(value: str) -> str:
    """Decode RFC 2047 encoded-words (UTF-8, GBK, ISO-8859-1, ...)."""
    if "=?" not in value:
        return value
    value = _BETWEEN_WORDS.sub(r"\1\2", value)
    return _ENCODED_WORD.sub(
        lambda m: _decode_word(m.group(1), m.group(2), m.group(3)), value
    )


def _split_params(value: str) -> list[str]:
    """Split a header value on ';' while respecting quoted strings."""
    parts, current, in_quote, escaped = [], [], False, False
    for ch in value:
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == "\\" and in_quote:
            escaped = True
        elif ch == '"':
            in_quote = not in_quote
            current.append(ch)
        elif ch == ";" and not in_quote:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return parts


def _unquote(token: str) -> str:
    token = token.strip()
    if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
        return token[1:-1]
    return token


def parse_structured_header(value: str) -> tuple[str, dict[str, str]]:
    """Parse e.g. Content-Type/Content-Disposition into (main, params)."""
    segments = _split_params(value)
    main = segments[0].strip().lower()
    params: dict[str, str] = {}
    for seg in segments[1:]:
        key, eq, val = seg.partition("=")
        if not eq:
            continue
        params[key.strip().lower()] = decode_rfc2047(_unquote(val))
    return main, params


def parse_content_type(value: str | None) -> tuple[str, dict[str, str]]:
    if not value:
        return "text/plain", {}
    main, params = parse_structured_header(value)
    return (main or "text/plain"), params


def parse_content_disposition(value: str | None) -> tuple[str, dict[str, str]]:
    if not value:
        return "", {}
    return parse_structured_header(value)
