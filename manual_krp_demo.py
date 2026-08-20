from pathlib import Path
import hashlib
import os
import tempfile
import threading

import ubin
from ubin.secure import SecureServer, generate_localhost_certificate


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


def run_once(server, result):
    try:
        result["receipt"] = server.serve_once()
    except Exception as exc:
        result["error"] = exc


with tempfile.TemporaryDirectory(prefix="ubin-v05-krp-demo-") as tmp:
    tmp = Path(tmp)
    cert = tmp / "localhost-cert.pem"
    key = tmp / "localhost-key.pem"
    received_dir = tmp / "received"
    client_state = tmp / "client-resume"

    generate_localhost_certificate(cert, key)

    source = tmp / "large.futureXYZ"
    frame_size = 64 * 1024
    source.write_bytes(os.urandom(frame_size * 6 + 123))

    server = SecureServer(
        host="127.0.0.1",
        port=0,
        certfile=cert,
        keyfile=key,
        output_dir=received_dir,
        _interrupt_once_after_frames=3,
    )

    first = {}
    first_thread = threading.Thread(target=run_once, args=(server, first))
    first_thread.start()

    interrupted = False
    try:
        ubin.secure(source).send(
            "127.0.0.1",
            port=server.port,
            cafile=cert,
            frame_size=frame_size,
            resume=True,
            permutation=True,
            state_dir=client_state,
        )
    except Exception:
        interrupted = True

    first_thread.join(timeout=10)

    second = {}
    second_thread = threading.Thread(target=run_once, args=(server, second))
    second_thread.start()

    sent = ubin.secure(source).send(
        "127.0.0.1",
        port=server.port,
        cafile=cert,
        frame_size=frame_size,
        resume=True,
        permutation=True,
        state_dir=client_state,
    )

    second_thread.join(timeout=10)
    server.close()

    if "error" in second:
        raise second["error"]

    received = received_dir / source.name

    print("KRP LAYOUT:", sent.layout)
    print("FIRST ATTEMPT INTERRUPTED:", interrupted)
    print("RESUMED FROM FRAME:", sent.resumed_from_frame)
    print("FRAMES SENT ON RESUME:", sent.frames_sent_this_attempt)
    print("TOTAL FRAMES:", sent.frame_count)
    print("TLS:", sent.tls_version)
    print("TRANSFER ID:", sent.transfer_id)
    print("Sender SHA-256:", sent.sha256)
    print("Receiver SHA-256:", second["receipt"].sha256)
    print("NO MANUAL KEY:", not hasattr(sent, "key"))
    print("NO KRP KEY EXPOSED:", not hasattr(sent, "permutation_key"))
    print("MATCH:", sha256(source) == sha256(received) == sent.sha256)
    print("CLIENT RESUME STATE CLEANED:", not list(client_state.glob("*.json")))
    print("FINAL FILE PUBLISHED:", received.exists())
