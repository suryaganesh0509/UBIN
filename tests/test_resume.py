from pathlib import Path
import hashlib
import json
import os
import threading

import pytest

import ubin
from ubin.errors import (
    UbinNetworkError,
    UbinResumeTicketError,
    UbinSourceChanged,
)
from ubin.secure import SecureServer, generate_localhost_certificate


def _run_once(server):
    result = {}

    def worker():
        try:
            result["receipt"] = server.serve_once()
        except BaseException as exc:
            result["error"] = exc

    thread = threading.Thread(target=worker)
    thread.start()
    return thread, result


@pytest.fixture
def tls_material(tmp_path: Path):
    cert = tmp_path / "server-cert.pem"
    key = tmp_path / "server-key.pem"
    generate_localhost_certificate(cert, key)
    return cert, key


def test_resumable_transfer_continues_from_durable_frame(
    tmp_path: Path,
    tls_material,
):
    cert, key = tls_material
    frame_size = 64 * 1024
    payload = os.urandom(frame_size * 6 + 123)
    source = tmp_path / "large.future"
    source.write_bytes(payload)
    output_dir = tmp_path / "received"
    client_state = tmp_path / "client-state"

    server = SecureServer(
        certfile=cert,
        keyfile=key,
        output_dir=output_dir,
        _interrupt_once_after_frames=3,
    )

    first_thread, first_result = _run_once(server)

    with pytest.raises((UbinNetworkError, OSError)):
        ubin.secure(source).send(
            "127.0.0.1",
            port=server.port,
            cafile=cert,
            frame_size=frame_size,
            resume=True,
            state_dir=client_state,
        )

    first_thread.join(timeout=10)
    assert not first_thread.is_alive()
    assert "error" in first_result
    assert not (output_dir / source.name).exists()
    assert list(client_state.glob("*.json"))
    assert list((output_dir / ".ubin-resume").glob("*.json"))
    assert list(output_dir.glob("*.ubin-part"))

    second_thread, second_result = _run_once(server)
    sent = ubin.secure(source).send(
        "127.0.0.1",
        port=server.port,
        cafile=cert,
        frame_size=frame_size,
        resume=True,
        state_dir=client_state,
    )
    second_thread.join(timeout=10)
    server.close()

    assert not second_thread.is_alive()
    assert "error" not in second_result
    assert sent.resumed_from_frame == 3
    assert sent.frames_sent_this_attempt == sent.frame_count - 3
    assert (output_dir / source.name).read_bytes() == payload
    assert not list(client_state.glob("*.json"))
    assert not list((output_dir / ".ubin-resume").glob("*.json"))


def test_resume_final_sha256_matches_source(
    tmp_path: Path,
    tls_material,
):
    cert, key = tls_material
    source = tmp_path / "data.bin"
    source.write_bytes(os.urandom(400_000))
    output_dir = tmp_path / "received"
    state_dir = tmp_path / "client-state"

    server = SecureServer(
        certfile=cert,
        keyfile=key,
        output_dir=output_dir,
    )
    thread, result = _run_once(server)

    sent = ubin.secure(source).send(
        "127.0.0.1",
        port=server.port,
        cafile=cert,
        frame_size=32 * 1024,
        resume=True,
        state_dir=state_dir,
    )
    thread.join(timeout=10)
    server.close()

    expected = hashlib.sha256(source.read_bytes()).hexdigest()
    assert sent.sha256 == expected
    assert result["receipt"].sha256 == expected
    assert (output_dir / source.name).read_bytes() == source.read_bytes()


def test_changed_source_is_rejected_before_resume(
    tmp_path: Path,
    tls_material,
):
    cert, key = tls_material
    frame_size = 32 * 1024
    source = tmp_path / "mutable.bin"
    source.write_bytes(os.urandom(frame_size * 5))
    output_dir = tmp_path / "received"
    client_state = tmp_path / "client-state"

    server = SecureServer(
        certfile=cert,
        keyfile=key,
        output_dir=output_dir,
        _interrupt_once_after_frames=2,
    )
    thread, result = _run_once(server)
    with pytest.raises((UbinNetworkError, OSError)):
        ubin.secure(source).send(
            "127.0.0.1",
            port=server.port,
            cafile=cert,
            frame_size=frame_size,
            resume=True,
            state_dir=client_state,
        )
    thread.join(timeout=10)

    source.write_bytes(b"changed" + source.read_bytes()[7:])

    with pytest.raises(UbinSourceChanged):
        ubin.secure(source).send(
            "127.0.0.1",
            port=server.port,
            cafile=cert,
            frame_size=frame_size,
            resume=True,
            state_dir=client_state,
        )

    server.close()
    assert not (output_dir / source.name).exists()


def test_tampered_client_resume_ticket_is_rejected(
    tmp_path: Path,
    tls_material,
):
    cert, key = tls_material
    frame_size = 32 * 1024
    source = tmp_path / "ticket.bin"
    source.write_bytes(os.urandom(frame_size * 4))
    output_dir = tmp_path / "received"
    client_state = tmp_path / "client-state"

    server = SecureServer(
        certfile=cert,
        keyfile=key,
        output_dir=output_dir,
        _interrupt_once_after_frames=2,
    )
    thread, _ = _run_once(server)
    with pytest.raises((UbinNetworkError, OSError)):
        ubin.secure(source).send(
            "127.0.0.1",
            port=server.port,
            cafile=cert,
            frame_size=frame_size,
            resume=True,
            state_dir=client_state,
        )
    thread.join(timeout=10)

    state_path = next(client_state.glob("*.json"))
    state = json.loads(state_path.read_text())
    state["ticket"] = "00" * 32
    state_path.write_text(json.dumps(state))

    thread2, result2 = _run_once(server)
    with pytest.raises(UbinNetworkError):
        ubin.secure(source).send(
            "127.0.0.1",
            port=server.port,
            cafile=cert,
            frame_size=frame_size,
            resume=True,
            state_dir=client_state,
        )
    thread2.join(timeout=10)
    server.close()

    assert "error" in result2
    assert not (output_dir / source.name).exists()


def test_corrupted_checkpointed_prefix_never_publishes(
    tmp_path: Path,
    tls_material,
):
    cert, key = tls_material
    frame_size = 32 * 1024
    source = tmp_path / "corrupt.bin"
    source.write_bytes(os.urandom(frame_size * 4 + 9))
    output_dir = tmp_path / "received"
    client_state = tmp_path / "client-state"

    server = SecureServer(
        certfile=cert,
        keyfile=key,
        output_dir=output_dir,
        _interrupt_once_after_frames=2,
    )
    thread, _ = _run_once(server)
    with pytest.raises((UbinNetworkError, OSError)):
        ubin.secure(source).send(
            "127.0.0.1",
            port=server.port,
            cafile=cert,
            frame_size=frame_size,
            resume=True,
            state_dir=client_state,
        )
    thread.join(timeout=10)

    partial = next(output_dir.glob("*.ubin-part"))
    raw = bytearray(partial.read_bytes())
    raw[0] ^= 0x80
    partial.write_bytes(raw)

    thread2, result2 = _run_once(server)
    with pytest.raises(UbinNetworkError):
        ubin.secure(source).send(
            "127.0.0.1",
            port=server.port,
            cafile=cert,
            frame_size=frame_size,
            resume=True,
            state_dir=client_state,
        )
    thread2.join(timeout=10)
    server.close()

    assert "error" in result2
    assert not (output_dir / source.name).exists()
    assert not partial.exists()


def test_resume_state_survives_server_restart(
    tmp_path: Path,
    tls_material,
):
    cert, key = tls_material
    frame_size = 32 * 1024
    source = tmp_path / "restart.bin"
    source.write_bytes(os.urandom(frame_size * 5 + 5))
    output_dir = tmp_path / "received"
    client_state = tmp_path / "client-state"

    server1 = SecureServer(
        certfile=cert,
        keyfile=key,
        output_dir=output_dir,
        _interrupt_once_after_frames=2,
    )
    port = server1.port
    thread, _ = _run_once(server1)
    with pytest.raises((UbinNetworkError, OSError)):
        ubin.secure(source).send(
            "127.0.0.1",
            port=port,
            cafile=cert,
            frame_size=frame_size,
            resume=True,
            state_dir=client_state,
        )
    thread.join(timeout=10)
    server1.close()

    server2 = SecureServer(
        host="127.0.0.1",
        port=port,
        certfile=cert,
        keyfile=key,
        output_dir=output_dir,
    )
    thread2, result2 = _run_once(server2)
    sent = ubin.secure(source).send(
        "127.0.0.1",
        port=port,
        cafile=cert,
        frame_size=frame_size,
        resume=True,
        state_dir=client_state,
    )
    thread2.join(timeout=10)
    server2.close()

    assert "error" not in result2
    assert sent.resumed_from_frame == 2
    assert (output_dir / source.name).read_bytes() == source.read_bytes()


def test_v03_non_resumable_network_path_still_works(
    tmp_path: Path,
    tls_material,
):
    cert, key = tls_material
    source = tmp_path / "legacy.bin"
    source.write_bytes(b"v0.3 compatibility")
    output_dir = tmp_path / "received"

    server = SecureServer(
        certfile=cert,
        keyfile=key,
        output_dir=output_dir,
    )
    thread, result = _run_once(server)
    receipt = ubin.secure(source).send(
        "127.0.0.1",
        port=server.port,
        cafile=cert,
        resume=False,
    )
    thread.join(timeout=10)
    server.close()

    assert "error" not in result
    assert not hasattr(receipt, "resumed_from_frame")
    assert (output_dir / source.name).read_bytes() == source.read_bytes()


def test_resumable_receipt_exposes_no_raw_key(
    tmp_path: Path,
    tls_material,
):
    cert, key = tls_material
    source = tmp_path / "nokey.bin"
    source.write_bytes(b"no raw key")
    output_dir = tmp_path / "received"

    server = SecureServer(
        certfile=cert,
        keyfile=key,
        output_dir=output_dir,
    )
    thread, result = _run_once(server)
    receipt = ubin.secure(source).send(
        "127.0.0.1",
        port=server.port,
        cafile=cert,
        resume=True,
        state_dir=tmp_path / "client-state",
    )
    thread.join(timeout=10)
    server.close()

    assert "error" not in result
    assert not hasattr(receipt, "key")
