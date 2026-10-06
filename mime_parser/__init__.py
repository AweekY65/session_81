"""Pure-local MIME (.eml) parser. No network, no external services."""

from .errors import (
    HeaderError,
    LimitExceededError,
    MimeParseError,
    TransferEncodingError,
    UnsafeFilenameError,
)
from .headers import decode_rfc2047
from .parser import Attachment, MimeParser, ParsedMessage
from .security import Limits, sanitize_filename
from .storage import save_attachments
from .transfer import decode_transfer

__all__ = [
    "Attachment",
    "HeaderError",
    "LimitExceededError",
    "Limits",
    "MimeParseError",
    "MimeParser",
    "ParsedMessage",
    "TransferEncodingError",
    "UnsafeFilenameError",
    "decode_rfc2047",
    "decode_transfer",
    "sanitize_filename",
    "save_attachments",
]
