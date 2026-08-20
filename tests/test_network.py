from pathlib import Path
import os
import ssl
import threading

import pytest

import ubin
from ubin.errors import UbinTLSVerificationError
from ubin.secure import generate_localhost_certificate
from ubin.secure.session import (
    create_hello,
    derive_session_key,
    parse_hello,
)


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


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"x",
        b"UBIN v0.3",
        os.urandom(2 * 1024 * 1024 + 123),
    ],
)
def test_tls_network_exact_round_trip(
    tmp_path: Path,
    tls_material,
    payload: bytes,
):
    cert, key = tls_material
    source = tmp_path / "anything.futureXYZ"
    source.write_bytes(payload)
    output_dir = tmp_path / "received"

    server = ubin.secure_server(
        certfile=cert,
        keyfile=key,
        output_dir=output_dir,
    )
    thread, result = _run_once(server)

    sent = ubin.secure(source).send(
        "127.0.0.1",
        port=server.port,
        cafile=cert,
        frame_size=257,
    )

    thread.join(timeout=10)
    server.close()

    assert not thread.is_alive()
    assert "error" not in result
    received = output_dir / source.name
    assert received.read_bytes() == payload

    recv = result["receipt"]
    assert sent.sha256 == recv.sha256
    assert sent.session_id == recv.session_id
    assert sent.transfer_id == recv.transfer_id
    assert sent.tls_version == "TLSv1.3"
    assert recv.tls_version == "TLSv1.3"


def test_network_send_receipt_exposes_no_raw_key(
    tmp_path: Path,
    tls_material,
):
    cert, key = tls_material
    source = tmp_path / "data.bin"
    source.write_bytes(b"secret-ish payload")
    output_dir = tmp_path / "received"

    server = ubin.secure_server(
        certfile=cert,
        keyfile=key,
        output_dir=output_dir,
    )
    thread, result = _run_once(server)

    sent = ubin.secure(source).send(
        "127.0.0.1",
        port=server.port,
        cafile=cert,
    )

    thread.join(timeout=10)
    server.close()

    assert "error" not in result
    assert not hasattr(sent, "key")


def test_untrusted_server_certificate_is_rejected(
    tmp_path: Path,
    tls_material,
):
    server_cert, server_key = tls_material

    wrong_cert = tmp_path / "wrong-cert.pem"
    wrong_key = tmp_path / "wrong-key.pem"
    generate_localhost_certificate(wrong_cert, wrong_key)

    source = tmp_path / "data.bin"
    source.write_bytes(b"payload")
    output_dir = tmp_path / "received"

    server = ubin.secure_server(
        certfile=server_cert,
        keyfile=server_key,
        output_dir=output_dir,
        timeout=2.0,
    )
    thread, result = _run_once(server)

    with pytest.raises(UbinTLSVerificationError):
        ubin.secure(source).send(
            "127.0.0.1",
            port=server.port,
            cafile=wrong_cert,
            timeout=2.0,
        )

    thread.join(timeout=5)
    server.close()
    assert not (output_dir / source.name).exists()


def test_x25519_handshake_derives_same_session_key():
    client_private, client_hello = create_hello()
    server_private, server_hello = create_hello()

    client_key = derive_session_key(
        client_private,
        parse_hello(server_hello),
        client_hello,
        server_hello,
    )
    server_key = derive_session_key(
        server_private,
        parse_hello(client_hello),
        client_hello,
        server_hello,
    )

    assert client_key == server_key
    assert len(client_key) == 32


def test_sessions_are_fresh(
    tmp_path: Path,
    tls_material,
):
    cert, key = tls_material
    source = tmp_path / "same.bin"
    source.write_bytes(b"same-file" * 100)

    session_ids = set()
    transfer_ids = set()

    for idx in range(2):
        output_dir = tmp_path / f"received-{idx}"
        server = ubin.secure_server(
            certfile=cert,
            keyfile=key,
            output_dir=output_dir,
        )
        thread, result = _run_once(server)

        sent = ubin.secure(source).send(
            "127.0.0.1",
            port=server.port,
            cafile=cert,
        )

        thread.join(timeout=10)
        server.close()
        assert "error" not in result
        session_ids.add(sent.session_id)
        transfer_ids.add(sent.transfer_id)

    assert len(session_ids) == 2
    assert len(transfer_ids) == 2
