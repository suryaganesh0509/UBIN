from __future__ import annotations

# Bounded, extension-independent signatures.
# Unknown data remains valid UBIN input and falls back to octet-stream.

_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"%PDF-", "application/pdf"),
    (b"PK\x03\x04", "application/zip"),
    (b"\x1f\x8b", "application/gzip"),
    (b"\x7fELF", "application/x-elf"),
    (b"MZ", "application/x-msdownload"),
    (b"\xfe\xed\xfa\xce", "application/x-mach-binary"),
    (b"\xce\xfa\xed\xfe", "application/x-mach-binary"),
    (b"\xfe\xed\xfa\xcf", "application/x-mach-binary"),
    (b"\xcf\xfa\xed\xfe", "application/x-mach-binary"),
)


def detect_type(prefix: bytes) -> str:
    for magic, mime in _SIGNATURES:
        if prefix.startswith(magic):
            return mime
    return "application/octet-stream"
