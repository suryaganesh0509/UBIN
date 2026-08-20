from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import secrets
import socket
import ssl
import tempfile
import threading
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..core import UbinObject
from ..errors import (
    UbinAuthenticationError,
    UbinCorruptionError,
    UbinNetworkError,
    UbinOutputExists,
    UbinProtocolError,
    UbinTLSVerificationError,
)
from .container import DEFAULT_SECURE_FRAME_SIZE
from .format import GCM_TAG_SIZE, MAX_FRAME_SIZE, frame_nonce
from .network_format import (
    ACK,
    ACK_MAGIC,
    ERROR_LEN,
    ERROR_MAGIC,
    FINAL_CIPHERTEXT_SIZE,
    FINAL_MAGIC,
    FINAL_META,
    FRAME_META,
    MAX_ERROR_BYTES,
    MAX_FILENAME_BYTES,
    TRANSFER_FIXED,
    TransferHeader,
    final_aad,
    frame_aad,
)
from .session import (
    HELLO,
    create_hello,
    derive_session_key,
    derive_transfer_key,
    parse_hello,
)

DEFAULT_TIMEOUT = 20.0


def _recv_exact(sock: ssl.SSLSocket, amount: int) -> bytes:
    if amount < 0:
        raise UbinProtocolError("negative network read size")

    parts = bytearray()
    while len(parts) < amount:
        block = sock.recv(amount - len(parts))
        if not block:
            raise UbinNetworkError("connection closed during UBIN transfer")
        parts.extend(block)
    return bytes(parts)


def _safe_send_error(sock: ssl.SSLSocket, message: str) -> None:
    try:
        raw = message.encode("utf-8", errors="replace")[:MAX_ERROR_BYTES]
        sock.sendall(ERROR_MAGIC + ERROR_LEN.pack(len(raw)) + raw)
    except Exception:
        pass


def _recv_ack_or_error(sock: ssl.SSLSocket, transfer_id: bytes):
    magic = _recv_exact(sock, 4)

    if magic == ERROR_MAGIC:
        length = ERROR_LEN.unpack(_recv_exact(sock, ERROR_LEN.size))[0]
        if length > MAX_ERROR_BYTES:
            raise UbinProtocolError("peer error message exceeds safety limit")
        message = _recv_exact(sock, length).decode("utf-8", errors="replace")
        raise UbinNetworkError(f"server rejected UBIN transfer: {message}")

    if magic != ACK_MAGIC:
        raise UbinProtocolError("invalid UBIN acknowledgement")

    remainder = _recv_exact(sock, ACK.size - 4)
    _, status, size, digest, ack_transfer_id = ACK.unpack(magic + remainder)
    if status != 1:
        raise UbinNetworkError("UBIN server returned unsuccessful status")
    if ack_transfer_id != transfer_id:
        raise UbinProtocolError("UBIN acknowledgement transfer id mismatch")

    return size, digest


def _client_context(
    *,
    cafile: str | os.PathLike[str],
    certfile: str | os.PathLike[str] | None = None,
    keyfile: str | os.PathLike[str] | None = None,
) -> ssl.SSLContext:
    try:
        context = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH,
            cafile=str(cafile),
        )
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        if certfile is not None:
            context.load_cert_chain(
                certfile=str(certfile),
                keyfile=None if keyfile is None else str(keyfile),
            )
        return context
    except (ssl.SSLError, OSError) as exc:
        raise UbinTLSVerificationError(
            f"could not configure UBIN TLS client: {exc}"
        ) from exc


def _server_context(
    *,
    certfile: str | os.PathLike[str],
    keyfile: str | os.PathLike[str],
    client_ca: str | os.PathLike[str] | None = None,
) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certfile=str(certfile), keyfile=str(keyfile))

    if client_ca is not None:
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(cafile=str(client_ca))

    return context


def _client_handshake(sock: ssl.SSLSocket) -> tuple[bytes, str]:
    private_key, client_hello = create_hello()
    sock.sendall(client_hello)

    server_hello = _recv_exact(sock, HELLO.size)
    server_public = parse_hello(server_hello)

    session_key = derive_session_key(
        private_key,
        server_public,
        client_hello,
        server_hello,
    )
    session_id = hashlib.sha256(client_hello + server_hello).hexdigest()[:32]
    return session_key, session_id


def _server_handshake(sock: ssl.SSLSocket) -> tuple[bytes, str]:
    client_hello = _recv_exact(sock, HELLO.size)
    client_public = parse_hello(client_hello)

    private_key, server_hello = create_hello()
    sock.sendall(server_hello)

    session_key = derive_session_key(
        private_key,
        client_public,
        client_hello,
        server_hello,
    )
    session_id = hashlib.sha256(client_hello + server_hello).hexdigest()[:32]
    return session_key, session_id


@dataclass(frozen=True, slots=True)
class NetworkSendReceipt:
    source: Path
    remote_host: str
    remote_port: int
    original_size: int
    frame_count: int
    sha256: str
    session_id: str
    transfer_id: str
    tls_version: str


@dataclass(frozen=True, slots=True)
class NetworkReceiveReceipt:
    output: Path
    original_size: int
    frame_count: int
    sha256: str
    session_id: str
    transfer_id: str
    tls_version: str


def send_secure_file(
    source,
    host: str,
    *,
    port: int,
    cafile,
    server_hostname: str | None = None,
    frame_size: int = DEFAULT_SECURE_FRAME_SIZE,
    timeout: float = DEFAULT_TIMEOUT,
    certfile=None,
    keyfile=None,
) -> NetworkSendReceipt:
    if not (1 <= frame_size <= MAX_FRAME_SIZE):
        raise ValueError(
            f"frame_size must be between 1 and {MAX_FRAME_SIZE} bytes"
        )

    with UbinObject(source) as obj:
        filename = obj.name
        original_size = obj.size
        frame_count = (
            0
            if original_size == 0
            else (original_size + frame_size - 1) // frame_size
        )

        transfer_id = secrets.token_bytes(16)
        nonce_base = secrets.token_bytes(12)
        transfer_header = TransferHeader(
            filename=filename,
            frame_size=frame_size,
            original_size=original_size,
            frame_count=frame_count,
            transfer_id=transfer_id,
            nonce_base=nonce_base,
        )
        transfer_header_bytes = transfer_header.pack()

        context = _client_context(
            cafile=cafile,
            certfile=certfile,
            keyfile=keyfile,
        )

        raw_sock = socket.create_connection((host, port), timeout=timeout)
        try:
            try:
                tls_sock = context.wrap_socket(
                    raw_sock,
                    server_hostname=server_hostname or host,
                )
            except ssl.SSLCertVerificationError as exc:
                raw_sock.close()
                raise UbinTLSVerificationError(
                    f"UBIN TLS server verification failed: {exc}"
                ) from exc
            except ssl.SSLError as exc:
                raw_sock.close()
                raise UbinNetworkError(
                    f"UBIN TLS handshake failed: {exc}"
                ) from exc

            with tls_sock:
                tls_sock.settimeout(timeout)
                tls_version = tls_sock.version() or "unknown"

                session_key, session_id = _client_handshake(tls_sock)
                transfer_key = derive_transfer_key(session_key, transfer_id)
                cipher = AESGCM(transfer_key)

                tls_sock.sendall(transfer_header_bytes)
                digest = hashlib.sha256()

                offset = 0
                for frame_number in range(frame_count):
                    plaintext_len = min(
                        frame_size,
                        original_size - offset,
                    )
                    plaintext = obj.read_at(offset, plaintext_len)
                    if len(plaintext) != plaintext_len:
                        raise UbinCorruptionError(
                            "source changed or became unreadable during send"
                        )

                    digest.update(plaintext)
                    aad = frame_aad(
                        transfer_header_bytes,
                        frame_number,
                        plaintext_len,
                    )
                    ciphertext = cipher.encrypt(
                        frame_nonce(nonce_base, frame_number),
                        plaintext,
                        aad,
                    )
                    meta = FRAME_META.pack(
                        frame_number,
                        plaintext_len,
                        len(ciphertext),
                    )
                    tls_sock.sendall(meta)
                    tls_sock.sendall(ciphertext)
                    offset += plaintext_len

                final_ciphertext = cipher.encrypt(
                    frame_nonce(nonce_base, frame_count),
                    digest.digest(),
                    final_aad(transfer_header_bytes),
                )
                tls_sock.sendall(
                    FINAL_META.pack(FINAL_MAGIC, len(final_ciphertext))
                )
                tls_sock.sendall(final_ciphertext)

                ack_size, ack_digest = _recv_ack_or_error(
                    tls_sock,
                    transfer_id,
                )
                if ack_size != original_size:
                    raise UbinProtocolError(
                        "server acknowledgement size mismatch"
                    )
                if not secrets.compare_digest(
                    ack_digest,
                    digest.digest(),
                ):
                    raise UbinAuthenticationError(
                        "server acknowledgement digest mismatch"
                    )

                return NetworkSendReceipt(
                    source=Path(obj.path),
                    remote_host=host,
                    remote_port=port,
                    original_size=original_size,
                    frame_count=frame_count,
                    sha256=digest.hexdigest(),
                    session_id=session_id,
                    transfer_id=transfer_id.hex(),
                    tls_version=tls_version,
                )
        finally:
            try:
                raw_sock.close()
            except Exception:
                pass


class SecureServer:
    """
    Small UBIN Secure v0.3 reference server.

    One `serve_once()` call accepts one connection and one file transfer.
    It is intentionally simple so the protocol can be tested before v0.4
    adds resumability and long-running production service behavior.
    """

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 0,
        certfile,
        keyfile,
        output_dir,
        timeout: float = DEFAULT_TIMEOUT,
        overwrite: bool = False,
        client_ca=None,
    ):
        self.host = host
        self.timeout = timeout
        self.output_dir = Path(output_dir).expanduser()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.overwrite = overwrite
        self._context = _server_context(
            certfile=certfile,
            keyfile=keyfile,
            client_ca=client_ca,
        )
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((host, port))
        self._listener.listen(5)
        self._listener.settimeout(timeout)
        self.port = self._listener.getsockname()[1]
        self.last_receipt: Optional[NetworkReceiveReceipt] = None
        self.last_error: Optional[BaseException] = None
        self._closed = False

    def close(self) -> None:
        if not self._closed:
            self._listener.close()
            self._closed = True

    def serve_once(self) -> NetworkReceiveReceipt:
        if self._closed:
            raise UbinNetworkError("UBIN server is closed")

        raw_conn, _address = self._listener.accept()
        raw_conn.settimeout(self.timeout)

        try:
            with self._context.wrap_socket(
                raw_conn,
                server_side=True,
            ) as tls_sock:
                tls_sock.settimeout(self.timeout)
                tls_version = tls_sock.version() or "unknown"

                try:
                    receipt = self._receive_one(tls_sock, tls_version)
                except Exception as exc:
                    self.last_error = exc
                    _safe_send_error(tls_sock, str(exc))
                    raise

                self.last_receipt = receipt
                self.last_error = None
                return receipt
        except ssl.SSLError as exc:
            self.last_error = exc
            raise UbinNetworkError(
                f"UBIN server TLS session failed: {exc}"
            ) from exc
        finally:
            try:
                raw_conn.close()
            except Exception:
                pass

    def _receive_one(
        self,
        tls_sock: ssl.SSLSocket,
        tls_version: str,
    ) -> NetworkReceiveReceipt:
        session_key, session_id = _server_handshake(tls_sock)

        fixed = _recv_exact(tls_sock, TRANSFER_FIXED.size)
        filename_len = TRANSFER_FIXED.unpack(fixed)[-1]
        if filename_len > MAX_FILENAME_BYTES:
            raise UbinProtocolError(
                "incoming UBIN filename exceeds safety limit"
            )
        filename_bytes = _recv_exact(tls_sock, filename_len)
        header = TransferHeader.unpack(fixed, filename_bytes)
        header_bytes = fixed + filename_bytes

        destination = self.output_dir / header.filename
        if destination.exists() and not self.overwrite:
            raise UbinOutputExists(
                f"destination already exists: {destination}"
            )

        transfer_key = derive_transfer_key(
            session_key,
            header.transfer_id,
        )
        cipher = AESGCM(transfer_key)

        fd, temp_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".ubin-part",
            dir=str(self.output_dir),
        )
        temp_path = Path(temp_name)

        digest = hashlib.sha256()
        restored_size = 0

        try:
            with os.fdopen(fd, "wb", buffering=0) as out:
                for expected_frame in range(header.frame_count):
                    meta_raw = _recv_exact(tls_sock, FRAME_META.size)
                    frame_number, plaintext_len, ciphertext_len = (
                        FRAME_META.unpack(meta_raw)
                    )

                    if frame_number != expected_frame:
                        raise UbinProtocolError(
                            "incoming frame order/number mismatch"
                        )
                    expected_plaintext_len = min(
                        header.frame_size,
                        header.original_size - restored_size,
                    )
                    if plaintext_len != expected_plaintext_len:
                        raise UbinProtocolError(
                            "incoming frame length mismatch"
                        )
                    if ciphertext_len != plaintext_len + GCM_TAG_SIZE:
                        raise UbinProtocolError(
                            "incoming ciphertext length mismatch"
                        )

                    ciphertext = _recv_exact(
                        tls_sock,
                        ciphertext_len,
                    )
                    aad = frame_aad(
                        header_bytes,
                        frame_number,
                        plaintext_len,
                    )
                    try:
                        plaintext = cipher.decrypt(
                            frame_nonce(
                                header.nonce_base,
                                frame_number,
                            ),
                            ciphertext,
                            aad,
                        )
                    except InvalidTag as exc:
                        raise UbinAuthenticationError(
                            "incoming UBIN frame authentication failed"
                        ) from exc

                    out.write(plaintext)
                    digest.update(plaintext)
                    restored_size += len(plaintext)

                if restored_size != header.original_size:
                    raise UbinCorruptionError(
                        "network-restored size mismatch"
                    )

                final_meta_raw = _recv_exact(
                    tls_sock,
                    FINAL_META.size,
                )
                final_magic, final_len = FINAL_META.unpack(
                    final_meta_raw
                )
                if final_magic != FINAL_MAGIC:
                    raise UbinProtocolError(
                        "missing UBIN network final record"
                    )
                if final_len != FINAL_CIPHERTEXT_SIZE:
                    raise UbinProtocolError(
                        "invalid UBIN network final record length"
                    )

                final_ciphertext = _recv_exact(tls_sock, final_len)
                try:
                    expected_digest = cipher.decrypt(
                        frame_nonce(
                            header.nonce_base,
                            header.frame_count,
                        ),
                        final_ciphertext,
                        final_aad(header_bytes),
                    )
                except InvalidTag as exc:
                    raise UbinAuthenticationError(
                        "UBIN final network authentication failed"
                    ) from exc

                actual_digest = digest.digest()
                if not secrets.compare_digest(
                    expected_digest,
                    actual_digest,
                ):
                    raise UbinAuthenticationError(
                        "UBIN network SHA-256 verification failed"
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

        tls_sock.sendall(
            ACK.pack(
                ACK_MAGIC,
                1,
                restored_size,
                digest.digest(),
                header.transfer_id,
            )
        )

        return NetworkReceiveReceipt(
            output=destination,
            original_size=restored_size,
            frame_count=header.frame_count,
            sha256=digest.hexdigest(),
            session_id=session_id,
            transfer_id=header.transfer_id.hex(),
            tls_version=tls_version,
        )
