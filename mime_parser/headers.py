"""RFC 5322 / RFC 2047 header parsing: unfolding, encoded-words, parameters."""

from __future__ import annotations

import codecs
import re
from dataclasses import dataclass, field

_BLANK_LINE = re.compile(rb"\r?\n\r?\n")
_ENCODED_WORD = re.compile(r"=\?([^?\s]+)\?([bBqQ])\?([^?]*)\?=")


def split_head_body(raw: bytes) -> tuple[bytes, bytes]:
    """Split a raw message/part into header block and body bytes."""
    match = _BLANK_LINE.search(raw)
    if match:
        return raw[: match.start()], raw[match.end() :]
    return raw, b""


def unfold_lines(head: bytes) -> list[bytes]:
    """Split a header block into logical lines, joining folded continuations."""
    lines: list[bytes] = []
    for line in head.split(b"\n"):
        line = line.rstrip(b"\r")
        if line[:1] in (b" ", b"\t") and lines:
            # Folded continuation: replace the fold with a single space.
            lines[-1] += b" " + line.strip()
        else:
            lines.append(line)
    return [line for line in lines if line]


def parse_headers(head: bytes) -> list[tuple[str, str]]:
    """Parse a header block into an ordered (name, raw-value) list."""
    headers: list[tuple[str, str]] = []
    for line in unfold_lines(head):
        name, sep, value = line.partition(b":")
        if not sep:
            continue  # Malformed line without a colon; skip it.
        headers.append(
            (name.decode("ascii", "replace").strip(), value.decode("utf-8", "replace").strip())
        )
    return headers


def _decode_charset(payload: bytes, charset: str) -> str:
    try:
        codecs.lookup(charset)
    except LookupError:
        charset = "utf-8"
    return payload.decode(charset, "replace")


def decode_rfc2047(value: str) -> str:
    """Decode MIME encoded-words (``=?charset?B/Q?...?=``) in a header value."""
    if "=?" not in value:
        return value
    out: list[str] = []
    pos = 0
    last_was_encoded = False
    for match in _ENCODED_WORD.finditer(value):
        between = value[pos : match.start()]
        # Whitespace between two adjacent encoded-words is not significant.
        if not (last_was_encoded and between.strip() == ""):
            out.append(between)
        charset, encoding, text = match.groups()
        try:
            if encoding in "bB":
                import base64

                payload = base64.b64decode(text, validate=False)
            else:
                payload = text.replace("_", " ").encode("latin-1")
                import quopri

                payload = quopri.decodestring(payload)
            out.append(_decode_charset(payload, charset))
        except Exception:
            out.append(match.group(0))  # Undecodable: keep the literal text.
        last_was_encoded = True
        pos = match.end()
    out.append(value[pos:])
    return "".join(out)


def _unquote(token: str) -> str:
    token = token.strip()
    if len(token) >= 2 and token[0] == '"' and token[-1] == '"':
        token = token[1:-1].replace('\\"', '"').replace("\\\\", "\\")
    return token


def split_params(value: str) -> tuple[str, dict[str, str]]:
    """Split a header value like ``text/plain; charset="utf-8"`` into the
    main token and a lower-cased parameter dict. Handles quoted strings."""
    parts: list[str] = []
    current: list[str] = []
    in_quote = False
    escape = False
    for ch in value:
        if escape:
            current.append(ch)
            escape = False
        elif ch == "\\" and in_quote:
            escape = True
        elif ch == '"':
            in_quote = not in_quote
            current.append(ch)
        elif ch == ";" and not in_quote:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))

    main = parts[0].strip().lower() if parts else ""
    params: dict[str, str] = {}
    for part in parts[1:]:
        name, sep, val = part.partition("=")
        if sep:
            params[name.strip().lower()] = _unquote(val)
    return main, params


@dataclass
class ContentType:
    maintype: str = "text"
    subtype: str = "plain"
    params: dict[str, str] = field(default_factory=dict)

    @property
    def full(self) -> str:
        return f"{self.maintype}/{self.subtype}"

    @property
    def charset(self) -> str:
        return self.params.get("charset", "utf-8")

    @property
    def boundary(self) -> str | None:
        return self.params.get("boundary")

    @property
    def name(self) -> str | None:
        return self.params.get("name")


def parse_content_type(value: str | None) -> ContentType:
    if not value:
        return ContentType()
    main, params = split_params(decode_rfc2047(value))
    if "/" in main:
        maintype, subtype = main.split("/", 1)
    elif main:
        maintype, subtype = main, ""
    else:
        maintype, subtype = "text", "plain"
    return ContentType(maintype.strip() or "text", subtype.strip() or "plain", params)


def parse_content_disposition(value: str | None) -> tuple[str | None, dict[str, str]]:
    if not value:
        return None, {}
    main, params = split_params(decode_rfc2047(value))
    return (main or None), params
