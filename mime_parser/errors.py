"""Exception types for the local MIME parser."""


class MimeParseError(Exception):
    """Base class for all MIME parsing errors."""


class TransferEncodingError(MimeParseError):
    """Raised when a content-transfer-encoding payload is invalid or truncated."""


class LimitExceededError(MimeParseError):
    """Raised when a configured safety limit (depth, count, size) is exceeded."""


class UnsafeFilenameError(MimeParseError):
    """Raised when an attachment filename cannot be made safe."""
