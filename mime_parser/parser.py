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
    parse_headers,
    split_head_body,
)
from .security import Limits, sanitize_filename
from .transfer import decode_transfer


@dataclass
class Attachment:
    filename: str  # sanitized, safe to join under an output directory
    original_filename: str | None
    content_type: str
    data: bytes

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass
class MailMessage:
    headers: list[tuple[str, str]] = field(default_factory=list)
    subject: str = ""
    from_: str = ""
    to: str = ""
    date: str = ""
    text_body: str | None = None
    html_body: str | None = None
    attachments: list[Attachment] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def header(self, name: str) -> str | None:
        name = name.lower()
        for key, value in self.headers:
            if key.lower() == name:
                return value
        return None


class MimeParser:
    """Parse RFC 5322 / MIME messages with safety limits.

    Args:
        limits: resource limits (depth, attachment count, decoded size).
        strict: when True, transfer-encoding corruption raises instead of
            being recorded as a warning on the message.
    """

    def __init__(self, limits: Limits | None = None, strict: bool = False):
        self.limits = limits or Limits()
        self.strict = strict
        self._decoded_bytes = 0
        self._message: MailMessage | None = None

    # ------------------------------------------------------------------ API

    def parse_file(self, path: str | Path) -> MailMessage:
        """Parse a local .eml file. The path must be a local filesystem path."""
        return self.parse_bytes(Path(path).read_bytes())

    def parse_bytes(self, raw: bytes) -> MailMessage:
        self._decoded_bytes = 0
        self._message = MailMessage()
        head, _ = split_head_body(raw)
        if len(head) > self.limits.max_header_bytes:
            raise LimitExceededError(
                f"header block exceeds {self.limits.max_header_bytes} bytes"
            )
        self._parse_part(raw, depth=1)
        msg = self._message
        msg.subject = decode_rfc2047(msg.header("subject") or "")
        msg.from_ = decode_rfc2047(msg.header("from") or "")
        msg.to = decode_rfc2047(msg.header("to") or "")
        msg.date = msg.header("date") or ""
        return msg

    # ------------------------------------------------------------- internals

    def _warn(self, text: str) -> None:
        assert self._message is not None
        self._message.warnings.append(text)

    def _decode_body(self, body: bytes, encoding: str, where: str) -> bytes:
        try:
            decoded = decode_transfer(body, encoding)
        except TransferEncodingError as exc:
            if self.strict:
                raise
            self._warn(f"{where}: {exc}; keeping undecoded content")
            return body
        self._decoded_bytes += len(decoded)
        if self._decoded_bytes > self.limits.max_total_bytes:
            raise LimitExceededError(
                f"decoded payload exceeds {self.limits.max_total_bytes} bytes"
            )
        return decoded

    def _decode_text(self, data: bytes, charset: str) -> str:
        try:
            codecs.lookup(charset)
        except LookupError:
            self._warn(f"unknown charset {charset!r}; falling back to utf-8")
            charset = "utf-8"
        return data.decode(charset, "replace")

    def _parse_part(self, raw: bytes, depth: int) -> None:
        if depth > self.limits.max_depth:
            raise LimitExceededError(
                f"MIME nesting depth exceeds limit of {self.limits.max_depth}"
            )
        head, body = split_head_body(raw)
        if len(head) > self.limits.max_header_bytes:
            raise LimitExceededError(
                f"header block exceeds {self.limits.max_header_bytes} bytes"
            )
        headers = parse_headers(head)
        header_map = {k.lower(): v for k, v in headers}
        assert self._message is not None
        if depth == 1:
            self._message.headers = headers

        ctype = parse_content_type(header_map.get("content-type"))
        encoding = header_map.get("content-transfer-encoding", "7bit")

        if ctype.maintype == "multipart" and ctype.boundary:
            for chunk in self._split_multipart(body, ctype.boundary):
                self._parse_part(chunk, depth + 1)
            return

        if ctype.full == "message/rfc822":
            # Embedded message: recurse into its content as a nested part.
            self._parse_part(body, depth + 1)
            return

        self._handle_leaf(headers, ctype, encoding, body, depth)

    def _handle_leaf(self, headers, ctype, encoding, body, depth) -> None:
        header_map = {k.lower(): v for k, v in headers}
        disposition, disp_params = parse_content_disposition(
            header_map.get("content-disposition")
        )
        filename = disp_params.get("filename") or ctype.name
        is_attachment = disposition == "attachment" or filename is not None
        where = f"part depth={depth} type={ctype.full}"

        if not is_attachment and ctype.maintype == "text":
            decoded = self._decode_body(body, encoding, where)
            text = self._decode_text(decoded, ctype.charset)
            self._add_text(ctype.subtype, text)
            return

        # Anything else is treated as an attachment (explicit or implicit).
        assert self._message is not None
        if len(self._message.attachments) >= self.limits.max_attachments:
            raise LimitExceededError(
                f"attachment count exceeds limit of {self.limits.max_attachments}"
            )
        decoded = self._decode_body(body, encoding, where)
        index = len(self._message.attachments)
        self._message.attachments.append(
            Attachment(
                filename=sanitize_filename(filename, index),
                original_filename=filename,
                content_type=ctype.full,
                data=decoded,
            )
        )

    def _add_text(self, subtype: str, text: str) -> None:
        assert self._message is not None
        if subtype == "html":
            self._message.html_body = (
                text if self._message.html_body is None else self._message.html_body + "\n" + text
            )
        else:
            self._message.text_body = (
                text if self._message.text_body is None else self._message.text_body + "\n" + text
            )

    @staticmethod
    def _split_multipart(body: bytes, boundary: str) -> list[bytes]:
        delimiter = b"--" + boundary.encode("latin-1", "replace")
        segments = body.split(delimiter)
        parts: list[bytes] = []
        for segment in segments[1:]:
            if segment.startswith(b"--"):  # closing delimiter: stop here
                break
            # Strip the CRLF that follows the delimiter and precedes the next.
            if segment.startswith(b"\r\n"):
                segment = segment[2:]
            elif segment.startswith(b"\n"):
                segment = segment[1:]
            if segment.endswith(b"\r\n"):
                segment = segment[:-2]
            elif segment.endswith(b"\n"):
                segment = segment[:-1]
            parts.append(segment)
        return parts
