from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import secrets
import tempfile

from .crypto import decrypt_aead, encrypt_aead, generate_key, validate_key
from .format import (
    FINAL_CIPHERTEXT_SIZE,
    FINAL_MAGIC,
    FINAL_META,
    FRAME_META,
    GCM_TAG_SIZE,
    HEADER_SIZE,
    MAX_FRAME_SIZE,
    SecureHeader,
    final_aad,
    frame_aad,
    frame_nonce,
)
from ..core import DEFAULT_BLOCK_SIZE, UbinObject
from ..errors import (
    UbinAuthenticationError,
    UbinCorruptionError,
    UbinInvalidHeader,
    UbinOutputExists,
)

DEFAULT_SECURE_FRAME_SIZE = 1024 * 1024  # 1 MiB


def _read_exact(file_obj, amount: int) -> bytes:
    if amount < 0:
        raise UbinCorruptionError("negative read size")
    data = file_obj.read(amount)
    if len(data) != amount:
        raise UbinCorruptionError("truncated UBIN Secure container")
    return data


def _check_destination(path: Path, overwrite: bool) -> None:
    if path.exists() and not overwrite:
        raise UbinOutputExists(
            f"destination already exists: {path}. "
            "Pass overwrite=True only when replacement is intended."
        )


def _same_path(a: Path, b: Path) -> bool:
    try:
        return a.resolve() == b.resolve()
    except OSError:
        return os.path.abspath(a) == os.path.abspath(b)


@dataclass(frozen=True, slots=True)
class SecureReceipt:
    output: Path
    key: bytes
    original_size: int
    frame_count: int
    sha256: str
    session_id: str


class SecureSource:
    __slots__ = ("_source", "_key")

    def __init__(self, source, key: bytes | None = None):
        self._source = source
        self._key = generate_key() if key is None else validate_key(key)

    @property
    def key(self) -> bytes:
        # Phase 0.2 exposes the ephemeral key so local encrypt/decrypt can be
        # tested. Phase 0.3 will replace this with automatic session key exchange.
        return self._key


    def send(
        self,
        host: str,
        *,
        port: int,
        cafile,
        server_hostname: str | None = None,
        frame_size: int = DEFAULT_SECURE_FRAME_SIZE,
        timeout: float = 20.0,
        certfile=None,
        keyfile=None,
    ):
        """
        Send the source through UBIN Secure v0.3.

        Unlike local v0.2 save/decrypt, the developer does not pass a raw
        encryption key. A fresh application-layer key is established from
        an ephemeral X25519 exchange inside the authenticated TLS channel.
        """
        from .network import send_secure_file

        return send_secure_file(
            self._source,
            host,
            port=port,
            cafile=cafile,
            server_hostname=server_hostname,
            frame_size=frame_size,
            timeout=timeout,
            certfile=certfile,
            keyfile=keyfile,
        )
    def save(
        self,
        destination,
        *,
        frame_size: int = DEFAULT_SECURE_FRAME_SIZE,
        overwrite: bool = False,
    ) -> SecureReceipt:
        if not (1 <= frame_size <= MAX_FRAME_SIZE):
            raise ValueError(
                f"frame_size must be between 1 and {MAX_FRAME_SIZE} bytes"
            )

        destination = Path(destination).expanduser()
        _check_destination(destination, overwrite)
        destination.parent.mkdir(parents=True, exist_ok=True)

        with UbinObject(self._source) as source:
            source_path = Path(source.path)
            if _same_path(source_path, destination):
                raise ValueError("secure destination must differ from source")

            original_size = source.size
            frame_count = (
                0
                if original_size == 0
                else (original_size + frame_size - 1) // frame_size
            )
            session_id = secrets.token_bytes(16)
            nonce_base = secrets.token_bytes(12)

            header = SecureHeader(
                frame_size=frame_size,
                original_size=original_size,
                frame_count=frame_count,
                session_id=session_id,
                nonce_base=nonce_base,
            )
            header_bytes = header.pack()

            digest = hashlib.sha256()

            # Same-directory temp file allows atomic os.replace on success.
            fd, temp_name = tempfile.mkstemp(
                prefix=f".{destination.name}.",
                suffix=".ubin-part",
                dir=str(destination.parent),
            )
            temp_path = Path(temp_name)

            try:
                with os.fdopen(fd, "wb", buffering=0) as out:
                    out.write(header_bytes)

                    offset = 0
                    for frame_number in range(frame_count):
                        remaining = original_size - offset
                        plaintext_len = min(frame_size, remaining)
                        plaintext = source.read_at(offset, plaintext_len)

                        if len(plaintext) != plaintext_len:
                            raise UbinCorruptionError(
                                "source changed or became unreadable during encryption"
                            )

                        digest.update(plaintext)

                        aad = frame_aad(
                            header_bytes,
                            frame_number,
                            plaintext_len,
                        )
                        nonce = frame_nonce(nonce_base, frame_number)
                        ciphertext = encrypt_aead(
                            self._key,
                            nonce,
                            plaintext,
                            aad,
                        )

                        out.write(
                            FRAME_META.pack(
                                frame_number,
                                plaintext_len,
                                len(ciphertext),
                            )
                        )
                        out.write(ciphertext)
                        offset += plaintext_len

                    # Authenticated final digest record.
                    final_digest = digest.digest()
                    final_counter = frame_count
                    final_ciphertext = encrypt_aead(
                        self._key,
                        frame_nonce(nonce_base, final_counter),
                        final_digest,
                        final_aad(header_bytes),
                    )
                    out.write(FINAL_META.pack(FINAL_MAGIC, len(final_ciphertext)))
                    out.write(final_ciphertext)

                    out.flush()
                    os.fsync(out.fileno())

                os.replace(temp_path, destination)

            except Exception:
                try:
                    temp_path.unlink(missing_ok=True)
                except Exception:
                    pass
                raise

            return SecureReceipt(
                output=destination,
                key=self._key,
                original_size=original_size,
                frame_count=frame_count,
                sha256=digest.hexdigest(),
                session_id=session_id.hex(),
            )


@dataclass(frozen=True, slots=True)
class RestoreReceipt:
    output: Path
    restored_size: int
    frame_count: int
    sha256: str
    session_id: str


def decrypt_file(
    secure_source,
    destination,
    *,
    key: bytes,
    overwrite: bool = False,
) -> RestoreReceipt:
    key = validate_key(key)
    secure_path = Path(secure_source).expanduser()
    destination = Path(destination).expanduser()

    _check_destination(destination, overwrite)
    destination.parent.mkdir(parents=True, exist_ok=True)

    if _same_path(secure_path, destination):
        raise ValueError("restore destination must differ from secure container")

    with secure_path.open("rb", buffering=0) as inp:
        raw_header = _read_exact(inp, HEADER_SIZE)
        header = SecureHeader.unpack(raw_header)

        fd, temp_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".ubin-part",
            dir=str(destination.parent),
        )
        temp_path = Path(temp_name)

        digest = hashlib.sha256()
        restored_size = 0

        try:
            with os.fdopen(fd, "wb", buffering=0) as out:
                for expected_frame_number in range(header.frame_count):
                    meta_raw = _read_exact(inp, FRAME_META.size)
                    frame_number, plaintext_len, ciphertext_len = FRAME_META.unpack(
                        meta_raw
                    )

                    if frame_number != expected_frame_number:
                        raise UbinCorruptionError(
                            "frame order/number mismatch"
                        )
                    if plaintext_len > header.frame_size:
                        raise UbinCorruptionError(
                            "frame plaintext length exceeds declared frame size"
                        )
                    if ciphertext_len != plaintext_len + GCM_TAG_SIZE:
                        raise UbinCorruptionError(
                            "invalid AES-GCM ciphertext length"
                        )

                    expected_plaintext_len = min(
                        header.frame_size,
                        header.original_size - restored_size,
                    )
                    if plaintext_len != expected_plaintext_len:
                        raise UbinCorruptionError(
                            "frame length is inconsistent with header"
                        )

                    ciphertext = _read_exact(inp, ciphertext_len)
                    aad = frame_aad(
                        raw_header,
                        frame_number,
                        plaintext_len,
                    )
                    plaintext = decrypt_aead(
                        key,
                        frame_nonce(header.nonce_base, frame_number),
                        ciphertext,
                        aad,
                    )

                    if len(plaintext) != plaintext_len:
                        raise UbinCorruptionError(
                            "decrypted frame length mismatch"
                        )

                    out.write(plaintext)
                    digest.update(plaintext)
                    restored_size += len(plaintext)

                if restored_size != header.original_size:
                    raise UbinCorruptionError(
                        "restored size does not match secure header"
                    )

                final_meta_raw = _read_exact(inp, FINAL_META.size)
                final_magic, final_ciphertext_len = FINAL_META.unpack(final_meta_raw)
                if final_magic != FINAL_MAGIC:
                    raise UbinCorruptionError("missing UBIN Secure final record")
                if final_ciphertext_len != FINAL_CIPHERTEXT_SIZE:
                    raise UbinCorruptionError("invalid final record length")

                final_ciphertext = _read_exact(inp, final_ciphertext_len)
                expected_digest = decrypt_aead(
                    key,
                    frame_nonce(header.nonce_base, header.frame_count),
                    final_ciphertext,
                    final_aad(raw_header),
                )

                actual_digest = digest.digest()
                if not secrets.compare_digest(expected_digest, actual_digest):
                    raise UbinAuthenticationError(
                        "final content digest verification failed"
                    )

                # No unauthenticated trailing bytes are accepted in 0.2.
                if inp.read(1) != b"":
                    raise UbinCorruptionError(
                        "unexpected trailing data after final record"
                    )

                out.flush()
                os.fsync(out.fileno())

            os.replace(temp_path, destination)

        except Exception:
            try:
                temp_path.unlink(missing_ok=True)
            except Exception:
                pass
            raise

    return RestoreReceipt(
        output=destination,
        restored_size=restored_size,
        frame_count=header.frame_count,
        sha256=digest.hexdigest(),
        session_id=header.session_id.hex(),
    )
