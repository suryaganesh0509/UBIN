class UbinError(Exception):
    """Base exception for UBIN."""


class UbinNotFound(UbinError):
    """The requested source does not exist."""


class UbinNotAFile(UbinError):
    """The requested source is not a regular file."""


class UbinPermissionDenied(UbinError):
    """UBIN cannot access the requested source."""


class UbinClosed(UbinError):
    """Operation attempted on a closed UBIN object."""


class UbinInvalidRange(UbinError):
    """Invalid offset/length/block-size request."""


class UbinSecureError(UbinError):
    """Base error for UBIN Secure."""


class UbinInvalidHeader(UbinSecureError):
    """Secure container header is invalid or unsupported."""


class UbinAuthenticationError(UbinSecureError):
    """Cryptographic authentication failed."""


class UbinCorruptionError(UbinSecureError):
    """Secure container is truncated, inconsistent, or corrupted."""


class UbinOutputExists(UbinSecureError):
    """Destination already exists and overwrite was not explicitly requested."""


class UbinKeyError(UbinSecureError):
    """The provided UBIN Secure key is invalid."""


class UbinNetworkError(UbinSecureError):
    """Base error for UBIN Secure network operations."""


class UbinProtocolError(UbinNetworkError):
    """The peer sent an invalid or unsupported UBIN network message."""


class UbinHandshakeError(UbinNetworkError):
    """UBIN application-level session establishment failed."""


class UbinTLSVerificationError(UbinNetworkError):
    """TLS peer certificate verification failed."""


class UbinResumeError(UbinNetworkError):
    """A resumable transfer cannot safely continue."""


class UbinResumeTicketError(UbinResumeError):
    """A resume ticket is invalid or does not match server state."""


class UbinSourceChanged(UbinResumeError):
    """The source changed since the resumable transfer started."""


class UbinCarrierError(UbinSecureError):
    """Lossless UBIN carrier is invalid, unsupported, or corrupted."""
