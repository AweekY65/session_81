"""Exception types for the local MIME parser."""


class MimeParseError(Exception):
    """Base class for all parser errors."""


class HeaderError(MimeParseError):
    """Malformed or oversized header block."""


class TransferEncodingError(MimeParseError):
    """Invalid or truncated content-transfer-encoding payload."""


class LimitExceededError(MimeParseError):
    """A configured resource limit (depth/attachments/bytes) was exceeded."""


class UnsafeFilenameError(MimeParseError):
    """Attachment filename or target path failed safety checks."""
