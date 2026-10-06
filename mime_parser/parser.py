"""Recursive, resource-limited local MIME message parser.

Parses .eml bytes entirely in memory. Never performs any network I/O.
"""

from __future__ import annotations

import codecs
from dataclasses import dataclass, field
from pathlib import Path

from .errors import LimitExceededError, TransferEncodingError
from .headers import (
    decode_rfc2047,
    parse_content_disposition,
    parse_content_type,
    split_head_body,
    unfold_headers,
)
from .security import Limits, sanitize_filename
from .transfer import decode_transfer


@dataclass
class Attachment:
    filename: str  # sanitized, safe single path component
    original_filename: str | None
    content_type: str
    data: bytes


@dataclass
class ParsedMessage:
    subject: str = ""
    from_: str = ""
    to: str = ""
    date: str = ""
    text_body: str | None = None
    html_body: str | None = None
    attachments: list[Attachment] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)


class MimeParser:
    """Parse local .eml bytes/files. All state stays in memory or on disk."""

    def __init__(self, limits: Limits | None = None, strict: bool = False):
        self.limits = limits or Limits()
        self.strict = strict
        self._msg: ParsedMessage | None = None
        self._total_bytes = 0

    def parse_file(self, path: str | Path) -> ParsedMessage:
        """Read a local .eml file and parse it. No network access."""
        return self.parse_bytes(Path(path).read_bytes())

    def parse_bytes(self, raw: bytes) -> ParsedMessage:
        self._msg = ParsedMessage()
        self._total_bytes = 0
        self._parse_part(raw, depth=1, is_root=True)
        return self._msg

    # -- internals ---------------------------------------------------------

    def _headers_of(self, head: bytes) -> dict[str, str]:
        if len(head) > self.limits.max_header_bytes:
            raise LimitExceededError(
                f"header block exceeds {self.limits.max_header_bytes} bytes"
            )
        result: dict[str, str] = {}
        for name, value in unfold_headers(head):
            key = name.lower()
            if key not in result:  # first occurrence wins
                result[key] = decode_rfc2047(value)
        return result

    def _decode_payload(self, body: bytes, headers: dict[str, str]) -> bytes:
        try:
            payload = decode_transfer(body, headers.get("content-transfer-encoding"))
        except TransferEncodingError:
            if self.strict:
                raise
            assert self._msg is not None
            self._msg.warnings.append(
                "corrupt content-transfer-encoding; raw payload kept"
            )
            payload = body
        self._total_bytes += len(payload)
        if self._total_bytes > self.limits.max_total_bytes:
            raise LimitExceededError(
                f"decoded payload exceeds {self.limits.max_total_bytes} bytes"
            )
        return payload

    def _decode_text(self, payload: bytes, params: dict[str, str]) -> str:
        charset = params.get("charset", "utf-8")
        try:
            name = codecs.lookup(charset).name
        except LookupError:
            name = "utf-8"
        return payload.decode(name, errors="replace")

    def _parse_part(self, raw: bytes, depth: int, is_root: bool = False) -> None:
        if depth > self.limits.max_depth:
            raise LimitExceededError(
                f"MIME nesting exceeds max depth {self.limits.max_depth}"
            )
        head, body = split_head_body(raw)
        headers = self._headers_of(head)
        ctype, cparams = parse_content_type(headers.get("content-type"))
        disposition, dparams = parse_content_disposition(
            headers.get("content-disposition")
        )

        if is_root:
            assert self._msg is not None
            msg = self._msg
            msg.subject = headers.get("subject", "")
            msg.from_ = headers.get("from", "")
            msg.to = headers.get("to", "")
            msg.date = headers.get("date", "")
            msg.headers = headers

        if ctype.startswith("multipart/"):
            boundary = cparams.get("boundary")
            if boundary:
                for chunk in self._split_multipart(body, boundary):
                    self._parse_part(chunk, depth + 1)
            return

        if ctype == "message/rfc822" and disposition != "attachment":
            payload = self._decode_payload(body, headers)
            self._parse_part(payload, depth + 1)
            return

        payload = self._decode_payload(body, headers)
        is_attachment = (
            disposition == "attachment"
            or (ctype not in ("text/plain", "text/html") and disposition != "inline")
        )
        if is_attachment:
            self._add_attachment(ctype, cparams, dparams, payload)
        elif ctype == "text/plain":
            assert self._msg is not None
            text = self._decode_text(payload, cparams)
            if self._msg.text_body is None:
                self._msg.text_body = text
        elif ctype == "text/html":
            assert self._msg is not None
            html = self._decode_text(payload, cparams)
            if self._msg.html_body is None:
                self._msg.html_body = html

    def _split_multipart(self, body: bytes, boundary: str) -> list[bytes]:
        delimiter = b"--" + boundary.encode("latin-1")
        chunks: list[bytes] = []
        for segment in body.split(delimiter)[1:]:
            if segment.startswith(b"--"):  # closing delimiter
                break
            if segment.startswith(b"\r\n"):
                segment = segment[2:]
            elif segment.startswith(b"\n"):
                segment = segment[1:]
            segment = segment.rstrip(b"\r\n")
            if segment:
                chunks.append(segment)
        return chunks

    def _add_attachment(
        self,
        ctype: str,
        cparams: dict[str, str],
        dparams: dict[str, str],
        payload: bytes,
    ) -> None:
        assert self._msg is not None
        if len(self._msg.attachments) >= self.limits.max_attachments:
            raise LimitExceededError(
                f"attachment count exceeds {self.limits.max_attachments}"
            )
        original = dparams.get("filename") or cparams.get("name")
        safe = sanitize_filename(
            original, fallback=f"attachment-{len(self._msg.attachments) + 1}"
        )
        self._msg.attachments.append(
            Attachment(
                filename=safe,
                original_filename=original,
                content_type=ctype,
                data=payload,
            )
        )
