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
