"""Resource limits and untrusted filename sanitization."""

from __future__ import annotations

import re
from dataclasses import dataclass

# Characters that are unsafe on common filesystems, plus ASCII control chars.
_UNSAFE_CHARS = re.compile(r'[<>:"|?*\x00-\x1f\x7f]')
_MAX_NAME_LEN = 255


@dataclass(frozen=True)
class Limits:
    """Hard resource limits guarding against malicious messages."""

    max_depth: int = 20                    # max MIME nesting depth
    max_attachments: int = 100             # max attachments per message
    max_total_bytes: int = 50 * 1024 * 1024  # max summed decoded payload bytes
    max_header_bytes: int = 256 * 1024     # max size of a single header block


def sanitize_filename(name: str | None, fallback: str = "attachment") -> str:
    """Turn an untrusted filename into a safe single path component.

    Strips any directory traversal (``../``, absolute POSIX/Windows paths),
    removes dangerous characters and leading dots, and truncates the result.
    """
    if not name:
        return fallback
    # Split on both separators so "a/b", "a\\b" and mixed forms collapse
    # to the final component; this defeats ../ and absolute paths.
    for sep in ("/", "\\"):
        name = name.rsplit(sep, 1)[-1]
    name = _UNSAFE_CHARS.sub("_", name)
    name = name.strip().lstrip(".")  # no hidden files, no ".." remnants
    name = name.strip()
    if not name:
        return fallback
    if len(name) > _MAX_NAME_LEN:
        stem, dot, ext = name.rpartition(".")
        if dot and len(ext) < 32:
            name = stem[: _MAX_NAME_LEN - len(ext) - 1] + "." + ext
        else:
            name = name[:_MAX_NAME_LEN]
    return name
