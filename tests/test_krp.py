from pathlib import Path
import os
import threading

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import ubin
from ubin.errors import UbinNetworkError
from ubin.secure import SecureServer, generate_localhost_certificate
from ubin.secure.krp import frame_context, permute_blocks, restore_blocks


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
    "size",
    [0, 1, 4095, 8192 + 117],
)
def test_krp_exact_round_trip_varied_sizes(size: int):
    data = os.urandom(size)
    key = os.urandom(32)
    context = b"test-context"

    transformed = permute_blocks(data, key, context=context)
    restored = restore_blocks(transformed, key, context=context)

    assert restored == data
    assert len(transformed) == len(data)


def test_krp_is_deterministic_but_context_bound():
    data = b"".join(i.to_bytes(4, "big") * 1024 for i in range(12))
    key = bytes(range(32))

    a1 = permute_blocks(data, key, context=b"frame-A")
    a2 = permute_blocks(data, key, context=b"frame-A")
    b = permute_blocks(data, key, context=b"frame-B")

    assert a1 == a2
    assert restore_blocks(a1, key, context=b"frame-A") == data
    assert a1 != data
    assert b != a1


def test_krp_tamper_still_fails_aes_gcm_authentication():
    enc_key = os.urandom(32)
    perm_key = os.urandom(32)
    nonce = os.urandom(12)
    aad = b"authenticated metadata"
    plaintext = os.urandom(32 * 1024)
    context = b"transfer-frame"

    ciphertext = AESGCM(enc_key).encrypt(nonce, plaintext, aad)
    wire = bytearray(permute_blocks(ciphertext, perm_key, context=context))
    wire[5000] ^= 0x01
    restored_ciphertext = restore_blocks(
        bytes(wire),
        perm_key,
        context=context,
    )

    with pytest.raises(InvalidTag):
        AESGCM(enc_key).decrypt(nonce, restored_ciphertext, aad)


def test_v05_krp_network_exact_round_trip(tmp_path: Path, tls_material):
    cert, key = tls_material
    frame_size = 64 * 1024
    source = tmp_path / "layout.future"
    source.write_bytes(os.urandom(frame_size * 3 + 777))
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
        frame_size=frame_size,
        resume=True,
        permutation=True,
        state_dir=state_dir,
    )

    thread.join(timeout=10)
    server.close()

    assert not thread.is_alive()
    assert "error" not in result
    received = output_dir / source.name
    assert received.read_bytes() == source.read_bytes()
    assert sent.sha256 == result["receipt"].sha256
    assert sent.layout == "krp"
    assert result["receipt"].layout == "krp"
    assert not hasattr(sent, "key")
    assert not hasattr(sent, "permutation_key")


def test_v05_krp_resumes_after_interruption(tmp_path: Path, tls_material):
    cert, key = tls_material
    frame_size = 64 * 1024
    source = tmp_path / "resume-krp.bin"
    source.write_bytes(os.urandom(frame_size * 6 + 321))
    output_dir = tmp_path / "received"
    state_dir = tmp_path / "client-state"

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
            permutation=True,
            state_dir=state_dir,
        )
    first_thread.join(timeout=10)
    assert "error" in first_result
    assert not (output_dir / source.name).exists()

    second_thread, second_result = _run_once(server)
    sent = ubin.secure(source).send(
        "127.0.0.1",
        port=server.port,
        cafile=cert,
        frame_size=frame_size,
        resume=True,
        permutation=True,
        state_dir=state_dir,
    )
    second_thread.join(timeout=10)
    server.close()

    assert "error" not in second_result
    assert sent.resumed_from_frame == 3
    assert sent.frames_sent_this_attempt == sent.frame_count - 3
    assert (output_dir / source.name).read_bytes() == source.read_bytes()
    assert not list(state_dir.glob("*.json"))


def test_v04_resume_mode_remains_compatible(tmp_path: Path, tls_material):
    cert, key = tls_material
    source = tmp_path / "v04.bin"
    source.write_bytes(b"v0.4 path remains intact" * 1000)
    output_dir = tmp_path / "received"

    server = SecureServer(certfile=cert, keyfile=key, output_dir=output_dir)
    thread, result = _run_once(server)
    receipt = ubin.secure(source).send(
        "127.0.0.1",
        port=server.port,
        cafile=cert,
        resume=True,
        permutation=False,
        state_dir=tmp_path / "v04-state",
    )
    thread.join(timeout=10)
    server.close()

    assert "error" not in result
    assert (output_dir / source.name).read_bytes() == source.read_bytes()
    assert receipt.sha256 == result["receipt"].sha256


def test_v05_permutation_requires_resumable_mode(tmp_path: Path):
    source = tmp_path / "x.bin"
    source.write_bytes(b"x")

    with pytest.raises(ValueError, match="requires resume=True"):
        ubin.secure(source).send(
            "127.0.0.1",
            port=1,
            cafile="unused.pem",
            permutation=True,
            resume=False,
        )


def test_frame_context_changes_per_frame():
    transfer_id = bytes(range(16))
    nonce_base = bytes(range(12))
    assert frame_context(transfer_id, nonce_base, 1) != frame_context(
        transfer_id,
        nonce_base,
        2,
    )
