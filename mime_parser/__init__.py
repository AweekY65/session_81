"""Local, offline MIME (.eml) parser with safety limits.

This package never performs network I/O: no SMTP, IMAP, Gmail, or any
external service. It only reads local bytes/files and local memory.
"""

from .errors import (
    LimitExceededError,
    MimeParseError,
    TransferEncodingError,
    UnsafeFilenameError,
)
from .parser import Attachment, MailMessage, MimeParser
from .security import Limits, sanitize_filename
from .storage import save_attachments

__all__ = [
    "Attachment",
    "LimitExceededError",
    "Limits",
    "MailMessage",
    "MimeParseError",
    "MimeParser",
    "TransferEncodingError",
    "UnsafeFilenameError",
    "sanitize_filename",
    "save_attachments",
]
