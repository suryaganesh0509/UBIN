from pathlib import Path
import hashlib
import tempfile
import threading

import ubin
from ubin.secure import generate_localhost_certificate


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


source = Path("sample.surya123")

with tempfile.TemporaryDirectory(prefix="ubin-v03-demo-") as tmp:
    tmp = Path(tmp)
    cert = tmp / "localhost-cert.pem"
    key = tmp / "localhost-key.pem"
    received_dir = tmp / "received"

    generate_localhost_certificate(cert, key)

    server = ubin.secure_server(
        host="127.0.0.1",
        port=0,
        certfile=cert,
        keyfile=key,
        output_dir=received_dir,
    )

    server_result = {}

    def run_server():
        try:
            server_result["receipt"] = server.serve_once()
        except Exception as exc:
            server_result["error"] = exc

    thread = threading.Thread(target=run_server)
    thread.start()

    try:
        sent = ubin.secure(source).send(
            "127.0.0.1",
            port=server.port,
            cafile=cert,
        )
    finally:
        thread.join(timeout=10)
        server.close()

    if "error" in server_result:
        raise server_result["error"]

    received = received_dir / source.name
    received_receipt = server_result["receipt"]

    print("TLS:", sent.tls_version)
    print("Source:", source)
    print("Received:", received)
    print("Frames:", sent.frame_count)
    print("Session ID:", sent.session_id)
    print("Transfer ID:", sent.transfer_id)
    print("Sender SHA-256:", sent.sha256)
    print("Receiver SHA-256:", received_receipt.sha256)
    print("NO MANUAL KEY:", not hasattr(sent, "key"))
    print("MATCH:", sha256(source) == sha256(received) == sent.sha256)
