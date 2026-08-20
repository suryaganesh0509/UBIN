from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import tempfile
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..core import UbinObject
from ..errors import (
    UbinAuthenticationError,
    UbinCorruptionError,
    UbinNetworkError,
    UbinOutputExists,
    UbinProtocolError,
    UbinResumeError,
    UbinResumeTicketError,
    UbinSourceChanged,
    UbinTLSVerificationError,
)
from .format import GCM_TAG_SIZE, MAX_FRAME_SIZE, frame_nonce
from .network_format import (
    ERROR_LEN,
    ERROR_MAGIC,
    FINAL_MAGIC,
    FINAL_META,
    FRAME_META,
    MAX_ERROR_BYTES,
    MAX_FILENAME_BYTES,
)
from .resume_format import (
    ACK,
    ACK_MAGIC,
    FINAL_CIPHERTEXT_SIZE,
    REQUEST,
    REQUEST_MAGIC,
    REQUEST_NEW,
    REQUEST_RESUME,
    STATUS,
    STATUS_MAGIC,
    STATUS_OK,
    TRANSFER_FIXED,
    TICKET_SIZE,
    ZERO_TICKET,
    ResumeTransferHeader,
    expected_bytes_for_next_frame,
    final_aad,
    frame_aad,
)
from .session import derive_transfer_key

DEFAULT_CLIENT_STATE_DIR = Path.home() / ".ubin" / "resume"
SERVER_SECRET_SIZE = 32


@dataclass(frozen=True, slots=True)
class ResumableSendReceipt:
    source: Path
    remote_host: str
    remote_port: int
    original_size: int
    frame_count: int
    sha256: str
    session_id: str
    transfer_id: str
    tls_version: str
    resumed_from_frame: int
    frames_sent_this_attempt: int


@dataclass(frozen=True, slots=True)
class ResumableReceiveReceipt:
    output: Path
    original_size: int
    frame_count: int
    sha256: str
    session_id: str
    transfer_id: str
    tls_version: str
    resumed_from_frame: int


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


def _recv_error(sock: ssl.SSLSocket) -> str:
    length = ERROR_LEN.unpack(_recv_exact(sock, ERROR_LEN.size))[0]
    if length > MAX_ERROR_BYTES:
        raise UbinProtocolError("peer error message exceeds safety limit")
    return _recv_exact(sock, length).decode("utf-8", errors="replace")


def _atomic_write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=str(path.parent),
    )
    temp = Path(temp_name)
    try:
        fchmod = getattr(os, "fchmod", None)
        if fchmod is not None:
            try:
                fchmod(fd, 0o600)
            except OSError:
                pass
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, sort_keys=True, separators=(",", ":"))
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp, path)
    except Exception:
        try:
            temp.unlink(missing_ok=True)
        except Exception:
            pass
        raise


def _read_json(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise UbinResumeError(f"invalid UBIN resume state: {path}") from exc


def _source_state_key(
    source_path: Path,
    host: str,
    port: int,
    server_hostname: str,
    frame_size: int,
) -> str:
    raw = "\0".join(
        [
            str(source_path.resolve()),
            host,
            str(port),
            server_hostname,
            str(frame_size),
        ]
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _client_state_path(
    *,
    source_path: Path,
    host: str,
    port: int,
    server_hostname: str,
    frame_size: int,
    state_dir,
) -> Path:
    directory = (
        DEFAULT_CLIENT_STATE_DIR
        if state_dir is None
        else Path(state_dir).expanduser()
    )
    return directory / (
        _source_state_key(
            source_path,
            host,
            port,
            server_hostname,
            frame_size,
        )
        + ".json"
    )


def _load_or_create_server_secret(server) -> bytes:
    if getattr(server, "_resume_secret", None) is not None:
        return server._resume_secret

    state_dir = Path(server._resume_state_dir)
    state_dir.mkdir(parents=True, exist_ok=True)
    path = Path(server._resume_secret_path)

    if path.exists():
        secret = path.read_bytes()
        if len(secret) != SERVER_SECRET_SIZE:
            raise UbinResumeError("invalid UBIN server resume secret")
    else:
        secret = secrets.token_bytes(SERVER_SECRET_SIZE)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(path, flags, 0o600)
        try:
            with os.fdopen(fd, "wb", buffering=0) as f:
                f.write(secret)
                f.flush()
                os.fsync(f.fileno())
        except Exception:
            try:
                path.unlink(missing_ok=True)
            except Exception:
                pass
            raise

    server._resume_secret = secret
    return secret


def _ticket_payload(header: ResumeTransferHeader) -> bytes:
    name = header.filename.encode("utf-8")
    return (
        b"UBIN-v0.4-resume-ticket\0"
        + header.transfer_id
        + header.source_sha256
        + header.original_size.to_bytes(8, "big")
        + header.frame_size.to_bytes(4, "big")
        + header.frame_count.to_bytes(8, "big")
        + len(name).to_bytes(2, "big")
        + name
    )


def _make_ticket(server, header: ResumeTransferHeader) -> bytes:
    secret = _load_or_create_server_secret(server)
    return hmac.new(
        secret,
        _ticket_payload(header),
        hashlib.sha256,
    ).digest()


def _server_state_path(server, transfer_id: bytes) -> Path:
    return Path(server._resume_state_dir) / f"{transfer_id.hex()}.json"


def _partial_path(server, header: ResumeTransferHeader) -> Path:
    return (
        Path(server.output_dir)
        / f".{header.filename}.{header.transfer_id.hex()}.ubin-part"
    )


def _stable_header_dict(header: ResumeTransferHeader) -> dict[str, Any]:
    return {
        "version": 1,
        "filename": header.filename,
        "frame_size": header.frame_size,
        "original_size": header.original_size,
        "frame_count": header.frame_count,
        "transfer_id": header.transfer_id.hex(),
        "source_sha256": header.source_sha256.hex(),
    }


def _write_server_state(
    server,
    header: ResumeTransferHeader,
    *,
    next_frame: int,
    bytes_received: int,
    partial_path: Path,
) -> None:
    state = _stable_header_dict(header)
    state.update(
        {
            "next_frame": next_frame,
            "bytes_received": bytes_received,
            "partial_name": partial_path.name,
        }
    )
    _atomic_write_json(
        _server_state_path(server, header.transfer_id),
        state,
    )


def _validate_server_state(
    server,
    header: ResumeTransferHeader,
) -> tuple[dict[str, Any], Path]:
    state_path = _server_state_path(server, header.transfer_id)
    if not state_path.exists():
        raise UbinResumeError("no resumable server state exists for transfer")

    state = _read_json(state_path)
    expected = _stable_header_dict(header)
    for key, value in expected.items():
        if state.get(key) != value:
            raise UbinResumeError(
                f"resume metadata mismatch for field: {key}"
            )

    next_frame = state.get("next_frame")
    bytes_received = state.get("bytes_received")
    if not isinstance(next_frame, int) or not isinstance(bytes_received, int):
        raise UbinResumeError("invalid resumable server checkpoint")

    expected_bytes = expected_bytes_for_next_frame(
        next_frame,
        header.frame_size,
        header.original_size,
        header.frame_count,
    )
    if bytes_received != expected_bytes:
        raise UbinResumeError("resume byte checkpoint is inconsistent")

    partial_name = state.get("partial_name")
    if not isinstance(partial_name, str):
        raise UbinResumeError("invalid partial-file checkpoint")
    partial_path = Path(server.output_dir) / partial_name

    if not partial_path.exists():
        raise UbinResumeError("resumable partial file is missing")

    actual_size = partial_path.stat().st_size
    if actual_size < bytes_received:
        raise UbinCorruptionError(
            "partial file is shorter than its durable checkpoint"
        )
    if actual_size > bytes_received:
        # Safe crash recovery: bytes beyond the committed checkpoint are
        # discarded. The client will resend them.
        with partial_path.open("r+b") as f:
            f.truncate(bytes_received)
            f.flush()
            os.fsync(f.fileno())

    return state, partial_path


def _discard_server_state(
    server,
    header: ResumeTransferHeader,
    partial_path: Path,
) -> None:
    try:
        partial_path.unlink(missing_ok=True)
    except Exception:
        pass
    try:
        _server_state_path(server, header.transfer_id).unlink(missing_ok=True)
    except Exception:
        pass


def _connect_tls(
    *,
    host: str,
    port: int,
    cafile,
    server_hostname: str,
    timeout: float,
    certfile=None,
    keyfile=None,
):
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

    raw_sock = socket.create_connection((host, port), timeout=timeout)
    try:
        try:
            tls_sock = context.wrap_socket(
                raw_sock,
                server_hostname=server_hostname,
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
        tls_sock.settimeout(timeout)
        return raw_sock, tls_sock
    except Exception:
        try:
            raw_sock.close()
        except Exception:
            pass
        raise


def send_resumable_file(
    source,
    host: str,
    *,
    port: int,
    cafile,
    server_hostname: str | None = None,
    frame_size: int,
    timeout: float,
    certfile=None,
    keyfile=None,
    state_dir=None,
) -> ResumableSendReceipt:
    if not (1 <= frame_size <= MAX_FRAME_SIZE):
        raise ValueError(
            f"frame_size must be between 1 and {MAX_FRAME_SIZE} bytes"
        )

    from .network import _client_handshake

    with UbinObject(source) as obj:
        source_path = Path(obj.path)
        filename = obj.name
        original_size = obj.size
        frame_count = (
            0
            if original_size == 0
            else (original_size + frame_size - 1) // frame_size
        )
        hostname = server_hostname or host
        state_path = _client_state_path(
            source_path=source_path,
            host=host,
            port=port,
            server_hostname=hostname,
            frame_size=frame_size,
            state_dir=state_dir,
        )

        # Strong source identity is required for safe resumption. This adds a
        # bounded-memory local SHA-256 pass before a resumable attempt.
        source_digest_hex = obj.hash("sha256")
        source_digest = bytes.fromhex(source_digest_hex)

        if state_path.exists():
            state = _read_json(state_path)
            if state.get("source_path") != str(source_path.resolve()):
                raise UbinResumeError("resume state belongs to another source")
            if state.get("source_sha256") != source_digest_hex:
                raise UbinSourceChanged(
                    "source content changed since transfer started"
                )
            if state.get("original_size") != original_size:
                raise UbinSourceChanged(
                    "source size changed since transfer started"
                )
            if state.get("frame_size") != frame_size:
                raise UbinResumeError("resume frame size changed")
            try:
                transfer_id = bytes.fromhex(state["transfer_id"])
                ticket = bytes.fromhex(state["ticket"])
            except (KeyError, ValueError, TypeError) as exc:
                raise UbinResumeError("invalid client resume state") from exc
            if len(transfer_id) != 16 or len(ticket) != TICKET_SIZE:
                raise UbinResumeError("invalid client resume identifiers")
            request_mode = REQUEST_RESUME
        else:
            transfer_id = secrets.token_bytes(16)
            ticket = ZERO_TICKET
            request_mode = REQUEST_NEW

        nonce_base = secrets.token_bytes(12)
        header = ResumeTransferHeader(
            filename=filename,
            frame_size=frame_size,
            original_size=original_size,
            frame_count=frame_count,
            transfer_id=transfer_id,
            nonce_base=nonce_base,
            source_sha256=source_digest,
        )
        header_bytes = header.pack()
        request_bytes = REQUEST.pack(
            REQUEST_MAGIC,
            request_mode,
            ticket,
        )

        raw_sock, tls_sock = _connect_tls(
            host=host,
            port=port,
            cafile=cafile,
            server_hostname=hostname,
            timeout=timeout,
            certfile=certfile,
            keyfile=keyfile,
        )
        try:
            with tls_sock:
                tls_version = tls_sock.version() or "unknown"
                session_key, session_id = _client_handshake(tls_sock)
                transfer_key = derive_transfer_key(
                    session_key,
                    transfer_id,
                )
                cipher = AESGCM(transfer_key)

                tls_sock.sendall(header_bytes)
                tls_sock.sendall(request_bytes)

                status_magic = _recv_exact(tls_sock, 4)
                if status_magic == ERROR_MAGIC:
                    message = _recv_error(tls_sock)
                    raise UbinNetworkError(
                        f"server rejected resumable transfer: {message}"
                    )
                if status_magic != STATUS_MAGIC:
                    raise UbinProtocolError(
                        "invalid UBIN resume status"
                    )

                status_rest = _recv_exact(tls_sock, STATUS.size - 4)
                status_bytes = status_magic + status_rest
                _, status, next_frame, bytes_received, server_ticket = (
                    STATUS.unpack(status_bytes)
                )
                if status != STATUS_OK:
                    raise UbinResumeError("server refused resume request")
                expected_bytes = expected_bytes_for_next_frame(
                    next_frame,
                    frame_size,
                    original_size,
                    frame_count,
                )
                if bytes_received != expected_bytes:
                    raise UbinProtocolError(
                        "server resume byte offset is inconsistent"
                    )
                if len(server_ticket) != TICKET_SIZE:
                    raise UbinProtocolError("invalid server resume ticket")

                if request_mode == REQUEST_RESUME and not secrets.compare_digest(
                    server_ticket,
                    ticket,
                ):
                    raise UbinResumeTicketError(
                        "server resume ticket changed unexpectedly"
                    )

                # Persist opaque resume authorization before the first frame.
                _atomic_write_json(
                    state_path,
                    {
                        "version": 1,
                        "source_path": str(source_path.resolve()),
                        "source_sha256": source_digest_hex,
                        "original_size": original_size,
                        "frame_size": frame_size,
                        "host": host,
                        "port": port,
                        "server_hostname": hostname,
                        "transfer_id": transfer_id.hex(),
                        "ticket": server_ticket.hex(),
                    },
                )

                offset = bytes_received
                sent_frames = 0

                for frame_number in range(next_frame, frame_count):
                    plaintext_len = min(
                        frame_size,
                        original_size - offset,
                    )
                    plaintext = obj.read_at(offset, plaintext_len)
                    if len(plaintext) != plaintext_len:
                        raise UbinSourceChanged(
                            "source changed or became unreadable during resume"
                        )

                    aad = frame_aad(
                        header_bytes,
                        status_bytes,
                        frame_number,
                        plaintext_len,
                    )
                    ciphertext = cipher.encrypt(
                        frame_nonce(nonce_base, frame_number),
                        plaintext,
                        aad,
                    )
                    tls_sock.sendall(
                        FRAME_META.pack(
                            frame_number,
                            plaintext_len,
                            len(ciphertext),
                        )
                    )
                    tls_sock.sendall(ciphertext)
                    offset += plaintext_len
                    sent_frames += 1

                final_ciphertext = cipher.encrypt(
                    frame_nonce(nonce_base, frame_count),
                    source_digest,
                    final_aad(header_bytes, status_bytes),
                )
                tls_sock.sendall(
                    FINAL_META.pack(
                        FINAL_MAGIC,
                        len(final_ciphertext),
                    )
                )
                tls_sock.sendall(final_ciphertext)

                ack_magic = _recv_exact(tls_sock, 4)
                if ack_magic == ERROR_MAGIC:
                    message = _recv_error(tls_sock)
                    raise UbinNetworkError(
                        f"server rejected resumable transfer: {message}"
                    )
                if ack_magic != ACK_MAGIC:
                    raise UbinProtocolError(
                        "invalid UBIN resumable acknowledgement"
                    )
                ack_rest = _recv_exact(tls_sock, ACK.size - 4)
                _, ack_status, ack_size, ack_digest, ack_transfer_id = (
                    ACK.unpack(ack_magic + ack_rest)
                )
                if ack_status != 1:
                    raise UbinNetworkError(
                        "UBIN resumable server returned failure"
                    )
                if ack_transfer_id != transfer_id:
                    raise UbinProtocolError(
                        "resumable acknowledgement transfer id mismatch"
                    )
                if ack_size != original_size:
                    raise UbinProtocolError(
                        "resumable acknowledgement size mismatch"
                    )
                if not secrets.compare_digest(
                    ack_digest,
                    source_digest,
                ):
                    raise UbinAuthenticationError(
                        "resumable acknowledgement digest mismatch"
                    )

                state_path.unlink(missing_ok=True)

                return ResumableSendReceipt(
                    source=source_path,
                    remote_host=host,
                    remote_port=port,
                    original_size=original_size,
                    frame_count=frame_count,
                    sha256=source_digest_hex,
                    session_id=session_id,
                    transfer_id=transfer_id.hex(),
                    tls_version=tls_version,
                    resumed_from_frame=next_frame,
                    frames_sent_this_attempt=sent_frames,
                )
        finally:
            try:
                raw_sock.close()
            except Exception:
                pass


def receive_resumable_after_magic(
    server,
    tls_sock: ssl.SSLSocket,
    tls_version: str,
    session_key: bytes,
    session_id: str,
    first_magic: bytes,
) -> ResumableReceiveReceipt:
    fixed = first_magic + _recv_exact(
        tls_sock,
        TRANSFER_FIXED.size - len(first_magic),
    )
    filename_len = TRANSFER_FIXED.unpack(fixed)[-1]
    if filename_len > MAX_FILENAME_BYTES:
        raise UbinProtocolError(
            "incoming UBIN filename exceeds safety limit"
        )
    filename_bytes = _recv_exact(tls_sock, filename_len)
    header = ResumeTransferHeader.unpack(fixed, filename_bytes)
    header_bytes = fixed + filename_bytes

    request_raw = _recv_exact(tls_sock, REQUEST.size)
    request_magic, request_mode, request_ticket = REQUEST.unpack(request_raw)
    if request_magic != REQUEST_MAGIC:
        raise UbinProtocolError("invalid UBIN resume request")
    if request_mode not in {REQUEST_NEW, REQUEST_RESUME}:
        raise UbinProtocolError("unsupported UBIN resume request mode")

    destination = Path(server.output_dir) / header.filename
    state_path = _server_state_path(server, header.transfer_id)
    ticket = _make_ticket(server, header)

    if request_mode == REQUEST_NEW:
        if not secrets.compare_digest(request_ticket, ZERO_TICKET):
            raise UbinResumeTicketError(
                "new transfer must not provide a resume ticket"
            )
        if state_path.exists():
            raise UbinResumeError("transfer id already has resumable state")
        if destination.exists() and not server.overwrite:
            raise UbinOutputExists(
                f"destination already exists: {destination}"
            )

        partial_path = _partial_path(server, header)
        if partial_path.exists():
            partial_path.unlink()
        fd = os.open(
            partial_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        os.close(fd)
        next_frame = 0
        bytes_received = 0
        _write_server_state(
            server,
            header,
            next_frame=next_frame,
            bytes_received=bytes_received,
            partial_path=partial_path,
        )
    else:
        if not secrets.compare_digest(request_ticket, ticket):
            raise UbinResumeTicketError("invalid UBIN resume ticket")
        state, partial_path = _validate_server_state(server, header)
        next_frame = int(state["next_frame"])
        bytes_received = int(state["bytes_received"])
        if destination.exists() and not server.overwrite:
            raise UbinOutputExists(
                f"destination already exists: {destination}"
            )

    status_bytes = STATUS.pack(
        STATUS_MAGIC,
        STATUS_OK,
        next_frame,
        bytes_received,
        ticket,
    )
    tls_sock.sendall(status_bytes)

    transfer_key = derive_transfer_key(session_key, header.transfer_id)
    cipher = AESGCM(transfer_key)

    resumed_from_frame = next_frame
    checkpoint_frame = next_frame
    current_bytes = bytes_received

    with partial_path.open("r+b", buffering=0) as out:
        out.seek(bytes_received)

        for expected_frame in range(next_frame, header.frame_count):
            meta_raw = _recv_exact(tls_sock, FRAME_META.size)
            frame_number, plaintext_len, ciphertext_len = FRAME_META.unpack(
                meta_raw
            )

            if frame_number != expected_frame:
                raise UbinProtocolError(
                    "incoming resumable frame order/number mismatch"
                )
            expected_plaintext_len = min(
                header.frame_size,
                header.original_size - current_bytes,
            )
            if plaintext_len != expected_plaintext_len:
                raise UbinProtocolError(
                    "incoming resumable frame length mismatch"
                )
            if ciphertext_len != plaintext_len + GCM_TAG_SIZE:
                raise UbinProtocolError(
                    "incoming resumable ciphertext length mismatch"
                )

            ciphertext = _recv_exact(tls_sock, ciphertext_len)
            aad = frame_aad(
                header_bytes,
                status_bytes,
                frame_number,
                plaintext_len,
            )
            try:
                plaintext = cipher.decrypt(
                    frame_nonce(header.nonce_base, frame_number),
                    ciphertext,
                    aad,
                )
            except InvalidTag as exc:
                raise UbinAuthenticationError(
                    "incoming resumable frame authentication failed"
                ) from exc

            out.write(plaintext)
            current_bytes += len(plaintext)
            checkpoint_frame = frame_number + 1

            # Durability ordering:
            # 1) plaintext to partial file
            # 2) fsync partial file
            # 3) atomically advance checkpoint
            out.flush()
            os.fsync(out.fileno())
            _write_server_state(
                server,
                header,
                next_frame=checkpoint_frame,
                bytes_received=current_bytes,
                partial_path=partial_path,
            )

            interrupt_after = getattr(
                server,
                "_interrupt_once_after_frames",
                None,
            )
            if (
                interrupt_after is not None
                and not getattr(server, "_interruption_triggered", False)
                and checkpoint_frame >= interrupt_after
            ):
                server._interruption_triggered = True
                try:
                    tls_sock.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                raise UbinNetworkError(
                    "simulated UBIN interruption after durable checkpoint"
                )

        if current_bytes != header.original_size:
            raise UbinCorruptionError(
                "resumable network-restored size mismatch"
            )

        final_meta_raw = _recv_exact(tls_sock, FINAL_META.size)
        final_magic, final_len = FINAL_META.unpack(final_meta_raw)
        if final_magic != FINAL_MAGIC:
            raise UbinProtocolError(
                "missing UBIN resumable final record"
            )
        if final_len != FINAL_CIPHERTEXT_SIZE:
            raise UbinProtocolError(
                "invalid UBIN resumable final record length"
            )

        final_ciphertext = _recv_exact(tls_sock, final_len)
        try:
            expected_digest = cipher.decrypt(
                frame_nonce(
                    header.nonce_base,
                    header.frame_count,
                ),
                final_ciphertext,
                final_aad(header_bytes, status_bytes),
            )
        except InvalidTag as exc:
            raise UbinAuthenticationError(
                "UBIN resumable final authentication failed"
            ) from exc

        if not secrets.compare_digest(
            expected_digest,
            header.source_sha256,
        ):
            raise UbinAuthenticationError(
                "sender final digest does not match transfer header"
            )

        out.flush()
        os.fsync(out.fileno())

    # Re-hash the complete partial file before publishing. This detects any
    # corruption of already-checkpointed bytes, including across restarts.
    actual = hashlib.sha256()
    with partial_path.open("rb") as f:
        while True:
            block = f.read(1024 * 1024)
            if not block:
                break
            actual.update(block)
    actual_digest = actual.digest()

    if not secrets.compare_digest(actual_digest, header.source_sha256):
        _discard_server_state(server, header, partial_path)
        raise UbinCorruptionError(
            "resumable partial file failed final SHA-256 verification"
        )

    os.replace(partial_path, destination)
    state_path.unlink(missing_ok=True)

    tls_sock.sendall(
        ACK.pack(
            ACK_MAGIC,
            1,
            header.original_size,
            actual_digest,
            header.transfer_id,
        )
    )

    return ResumableReceiveReceipt(
        output=destination,
        original_size=header.original_size,
        frame_count=header.frame_count,
        sha256=actual.hexdigest(),
        session_id=session_id,
        transfer_id=header.transfer_id.hex(),
        tls_version=tls_version,
        resumed_from_frame=resumed_from_frame,
    )
