"""Safe on-disk attachment storage. Local filesystem only."""

from __future__ import annotations

from pathlib import Path

from .errors import UnsafeFilenameError
from .parser import Attachment, ParsedMessage
from .security import sanitize_filename


def _unique_path(directory: Path, filename: str) -> Path:
    candidate = directory / filename
    if not candidate.exists():
        return candidate
    stem, dot, ext = filename.rpartition(".")
    for i in range(1, 1000):
        name = f"{stem}_{i}{dot}{ext}" if dot else f"{filename}_{i}"
        candidate = directory / name
        if not candidate.exists():
            return candidate
    raise UnsafeFilenameError(f"cannot find a free name for {filename!r}")


def save_attachments(
    msg: ParsedMessage, out_dir: str | Path
) -> list[Path]:
    """Write attachments under out_dir, refusing any path escape."""
    root = Path(out_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for att in msg.attachments:
        safe = sanitize_filename(att.filename)
        target = _unique_path(root, safe).resolve()
        if root != target.parent and root not in target.parents:
            raise UnsafeFilenameError(
                f"refusing to write outside output directory: {att.filename!r}"
            )
        target.write_bytes(att.data)
        written.append(target)
    return written
