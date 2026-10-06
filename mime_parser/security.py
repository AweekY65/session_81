"""Safety limits and filename sanitization for the local MIME parser."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Limits:
    """Resource limits guarding against malicious or pathological messages."""

    max_depth: int = 20
    max_attachments: int = 100
    max_total_bytes: int = 50 * 1024 * 1024  # 50 MiB of decoded payload
    max_header_bytes: int = 256 * 1024


# Characters that are unsafe on common filesystems or in shell contexts.
_UNSAFE_CHARS = re.compile(r'[<>:"|?*\x00-\x1f\x7f]')
_FALLBACK_PREFIX = "attachment"


def sanitize_filename(name: str | None, index: int = 0) -> str:
    """Reduce an attacker-controlled filename to a safe basename.

    Strips any directory components (both ``/`` and ``\\`` styles, so
    ``../`` and absolute paths cannot escape the target directory), removes
    control characters, and falls back to a generated name when nothing
    usable remains.
    """
    if not name:
        return f"{_FALLBACK_PREFIX}-{index}"
    # Normalize Windows separators, then keep only the final component.
    name = name.replace("\\", "/")
    name = name.rsplit("/", 1)[-1]
    # Remove control / shell-hostile characters.
    name = _UNSAFE_CHARS.sub("_", name)
    # Strip leading dots so ".." / ".hidden" / "...." can never be a path
    # segment of their own.
    name = name.lstrip(".")
    name = name.strip()
    if not name:
        return f"{_FALLBACK_PREFIX}-{index}"
    # Guard against absurdly long names.
    return name[:255]
