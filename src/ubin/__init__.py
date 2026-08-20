from __future__ import annotations

from .core import UbinInfo, UbinMemoryObject, UbinObject, UbinStreamObject
from .secure import (
    ImageCarrierReceipt,
    ImageRestoreReceipt,
    SecureServer,
    SecureSource,
    create_image_carrier,
    decrypt_file,
    restore_image_carrier,
)
from .errors import (
    UbinAuthenticationError,
    UbinCarrierError,
    UbinClosed,
    UbinCorruptionError,
    UbinError,
    UbinHandshakeError,
    UbinInvalidHeader,
    UbinInvalidRange,
    UbinKeyError,
    UbinNetworkError,
    UbinNotAFile,
    UbinNotFound,
    UbinOutputExists,
    UbinPermissionDenied,
    UbinProtocolError,
    UbinResumeError,
    UbinResumeTicketError,
    UbinSecureError,
    UbinSourceChanged,
    UbinTLSVerificationError,
)

__version__ = "1.0.1"


def open(source, *, name=None):
    """
    Public UBIN entry point for paths, bytes-like buffers, or seekable binary streams.

    Examples:
        ubin.open("anything.bin")
        ubin.open(b"raw bytes", name="packet.bin")
        ubin.open(io.BytesIO(b"stream bytes"), name="stream.bin")
    """
    import os

    if isinstance(source, (str, os.PathLike)):
        return UbinObject(source)
    if isinstance(source, (bytes, bytearray, memoryview)):
        return UbinMemoryObject(source, name=name or "memory.bin")
    if all(hasattr(source, attr) for attr in ("read", "seek", "tell")):
        return UbinStreamObject(source, name=name or getattr(source, "name", "stream.bin"))
    raise TypeError("UBIN source must be a path, bytes-like buffer, or seekable binary stream")


__all__ = [
    "open",
    "UbinObject",
    "UbinMemoryObject",
    "UbinStreamObject",
    "UbinInfo",
    "UbinError",
    "UbinNotFound",
    "UbinNotAFile",
    "UbinPermissionDenied",
    "UbinClosed",
    "UbinInvalidRange",
    "UbinSecureError",
    "UbinInvalidHeader",
    "UbinAuthenticationError",
    "UbinCorruptionError",
    "UbinOutputExists",
    "UbinKeyError",
    "UbinNetworkError",
    "UbinProtocolError",
    "UbinHandshakeError",
    "UbinTLSVerificationError",
    "UbinResumeError",
    "UbinResumeTicketError",
    "UbinSourceChanged",
    "UbinCarrierError",
]


def secure(source, *, key=None) -> SecureSource:
    """
    Create a UBIN Secure source.

    Local v0.2 container:
        receipt = ubin.secure("file.bin").save("file.ubs")
        ubin.decrypt("file.ubs", "restored.bin", key=receipt.key)

    Network v0.3:
        ubin.secure("file.bin").send(...)

    Resumable network v0.4:
        ubin.secure("file.bin").send(..., resume=True)

    KRP layout v0.5:
        ubin.secure("file.bin").send(..., resume=True, permutation=True)
    """
    return SecureSource(source, key=key)


def decrypt(secure_source, destination, *, key, overwrite=False):
    """Restore an authenticated UBIN Secure 0.2 container."""
    return decrypt_file(
        secure_source,
        destination,
        key=key,
        overwrite=overwrite,
    )


def secure_server(
    *,
    host="127.0.0.1",
    port=0,
    certfile,
    keyfile,
    output_dir,
    timeout=20.0,
    overwrite=False,
    client_ca=None,
    resume_state_dir=None,
):
    """Create a UBIN Secure server supporting v0.3-v0.5 transfer modes."""
    return SecureServer(
        host=host,
        port=port,
        certfile=certfile,
        keyfile=keyfile,
        output_dir=output_dir,
        timeout=timeout,
        overwrite=overwrite,
        client_ca=client_ca,
        resume_state_dir=resume_state_dir,
    )


def to_image(
    source,
    destination,
    *,
    passphrase,
    frame_size=1024 * 1024,
    krp_block_size=4096,
    width=1024,
    overwrite=False,
):
    """Create a lossless authenticated UBIN v1 PNG carrier."""
    return create_image_carrier(
        source,
        destination,
        passphrase=passphrase,
        frame_size=frame_size,
        krp_block_size=krp_block_size,
        width=width,
        overwrite=overwrite,
    )


def from_image(
    carrier,
    destination=None,
    *,
    passphrase,
    krp_block_size=4096,
    overwrite=False,
):
    """Restore a file from a lossless authenticated UBIN v1 PNG carrier."""
    return restore_image_carrier(
        carrier,
        destination,
        passphrase=passphrase,
        krp_block_size=krp_block_size,
        overwrite=overwrite,
    )


__all__ += [
    "secure", "decrypt", "secure_server", "to_image", "from_image",
    "ImageCarrierReceipt", "ImageRestoreReceipt",
]
