from __future__ import annotations

from .core import UbinInfo, UbinObject
from .errors import (
    UbinClosed,
    UbinError,
    UbinInvalidRange,
    UbinNotAFile,
    UbinNotFound,
    UbinPermissionDenied,
)

__version__ = "0.1.0"


def open(source) -> UbinObject:
    """
    Public UBIN entry point.

    Example:
        import ubin
        with ubin.open("anything.bin") as x:
            print(x.info())
    """
    return UbinObject(source)


__all__ = [
    "open",
    "UbinObject",
    "UbinInfo",
    "UbinError",
    "UbinNotFound",
    "UbinNotAFile",
    "UbinPermissionDenied",
    "UbinClosed",
    "UbinInvalidRange",
]
