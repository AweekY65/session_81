"""Safe local attachment extraction."""

from __future__ import annotations

from pathlib import Path

from .errors import UnsafeFilenameError
from .parser import MailMessage


def save_attachments(message: MailMessage, outdir: str | Path) -> list[Path]:
    """Write attachments into ``outdir`` using sanitized, unique filenames.

    Every written path is verified to stay inside ``outdir``; anything else
    raises :class:`UnsafeFilenameError` instead of writing.
    """
    outdir = Path(outdir).resolve()
    outdir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    used: set[str] = set()
    for attachment in message.attachments:
        name = attachment.filename
        if name in used:
            stem, dot, suffix = name.rpartition(".")
            counter = 1
            while name in used:
                candidate = f"{stem}_{counter}{dot}{suffix}" if dot else f"{name}_{counter}"
                name = candidate
                counter += 1
        used.add(name)
        target = (outdir / name).resolve()
        if target.parent != outdir or not str(target).startswith(str(outdir) + "/"):
            raise UnsafeFilenameError(
                f"refusing to write {attachment.original_filename!r} outside {outdir}"
            )
        target.write_bytes(attachment.data)
        written.append(target)
    return written
