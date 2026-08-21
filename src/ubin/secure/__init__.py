from __future__ import annotations

from importlib import import_module
import inspect
import sys
from types import ModuleType

_LAZY_ATTRS = {
    "DEFAULT_SECURE_FRAME_SIZE": (".container", "DEFAULT_SECURE_FRAME_SIZE"),
    "RestoreReceipt": (".container", "RestoreReceipt"),
    "SecureReceipt": (".container", "SecureReceipt"),
    "SecureSource": (".container", "SecureSource"),
    "decrypt_file": (".container", "decrypt_file"),
    "generate_key": (".crypto", "generate_key"),
    "NetworkReceiveReceipt": (".network", "NetworkReceiveReceipt"),
    "NetworkSendReceipt": (".network", "NetworkSendReceipt"),
    "SecureServer": (".network", "SecureServer"),
    "send_secure_file": (".network", "send_secure_file"),
    "generate_localhost_certificate": (".devcert", "generate_localhost_certificate"),
    "ResumableReceiveReceipt": (".resume", "ResumableReceiveReceipt"),
    "ResumableSendReceipt": (".resume", "ResumableSendReceipt"),
    "send_resumable_file": (".resume", "send_resumable_file"),
    "DEFAULT_KRP_BLOCK_SIZE": (".krp", "DEFAULT_KRP_BLOCK_SIZE"),
    "UbinPermutationError": (".krp", "UbinPermutationError"),
    "frame_context": (".krp", "frame_context"),
    "permute_blocks": (".krp", "permute_blocks"),
    "restore_blocks": (".krp", "restore_blocks"),
    "KrpReceiveReceipt": (".krp_transfer", "KrpReceiveReceipt"),
    "KrpSendReceipt": (".krp_transfer", "KrpSendReceipt"),
    "send_krp_resumable_file": (".krp_transfer", "send_krp_resumable_file"),
    "ImageCarrierReceipt": (".image_carrier", "ImageCarrierReceipt"),
    "ImageRestoreReceipt": (".image_carrier", "ImageRestoreReceipt"),
    "create_image_carrier": (".image_carrier", "create_image_carrier"),
    "restore_image_carrier": (".image_carrier", "restore_image_carrier"),
}


def __getattr__(name: str):
    target = _LAZY_ATTRS.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr_name = target
    module = import_module(module_name, __name__)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value


def __dir__():
    return sorted(set(globals()) | set(__all__))


def _public_secure_signature(source, *, key=None):
    """Signature template for the callable security namespace."""


class _SecureModule(ModuleType):
    """Compatibility bridge: ``ubin.secure`` is both namespace and callable."""

    def __call__(self, source, *, key=None):
        return self.SecureSource(source, key=key)


_module = sys.modules[__name__]
_module.__class__ = _SecureModule
_module.__signature__ = inspect.signature(_public_secure_signature)


__all__ = [
    "SecureSource",
    "SecureReceipt",
    "RestoreReceipt",
    "decrypt_file",
    "generate_key",
    "DEFAULT_SECURE_FRAME_SIZE",
    "SecureServer",
    "NetworkSendReceipt",
    "NetworkReceiveReceipt",
    "send_secure_file",
    "generate_localhost_certificate",
    "ResumableSendReceipt",
    "ResumableReceiveReceipt",
    "send_resumable_file",
    "DEFAULT_KRP_BLOCK_SIZE",
    "UbinPermutationError",
    "permute_blocks",
    "restore_blocks",
    "frame_context",
    "KrpSendReceipt",
    "KrpReceiveReceipt",
    "send_krp_resumable_file",
    "ImageCarrierReceipt",
    "ImageRestoreReceipt",
    "create_image_carrier",
    "restore_image_carrier",
]
