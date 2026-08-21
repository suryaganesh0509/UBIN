#!/usr/bin/env python3
"""
UBIN v1.0.4 public-consumer integration test.

Normal public usage after PyPI publication:
    python3 -m pip install ubin
    python3 examples/public_consumer_test.py

Right now, before the PyPI release exists, install the tagged GitHub release:
    python3 -m pip install "git+https://github.com/suryaganesh0509/UBIN.git@v1.0.4"

Optional one-command bootstrap:
    python3 examples/public_consumer_test.py --install

`--install` installs the exact v1.0.4 GitHub tag only when UBIN is missing.

This is a consumer-facing integration/smoke test. It exercises every major
public feature in one file. It is not a replacement for UBIN's internal
116-case pytest suite when the dev dependencies are installed.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading


GITHUB_V1 = (
    "git+https://github.com/suryaganesh0509/UBIN.git@v1.0.4"
)
EXPECTED_VERSION = "1.0.4"


def load_ubin(auto_install: bool):
    try:
        import ubin
        return ubin
    except ModuleNotFoundError:
        if not auto_install:
            print("\nUBIN is not installed in this Python interpreter.")
            print("Install v1.0.4 from GitHub:")
            print(
                '  python3 -m pip install '
                '"git+https://github.com/suryaganesh0509/UBIN.git@v1.0.4"'
            )
            print("\nAfter the PyPI release is published, users can use:")
            print("  python3 -m pip install ubin")
            print("\nOr run this file once with:")
            print("  python3 examples/public_consumer_test.py --install")
            raise SystemExit(2)

        print("UBIN is missing. Installing tagged UBIN v1.0.4 from GitHub...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", GITHUB_V1]
        )
        import ubin
        return ubin


parser = argparse.ArgumentParser(
    description="Run UBIN v1.0.4 public-consumer integration tests."
)
parser.add_argument(
    "--install",
    action="store_true",
    help="Install the tagged UBIN v1.0.4 GitHub release if UBIN is missing.",
)
args = parser.parse_args()

ubin = load_ubin(args.install)

# Test-only helper APIs shipped by UBIN for localhost demonstrations.
from ubin.secure import SecureServer, generate_localhost_certificate


PASS = 0
FAIL = 0


def check(name: str, condition: bool, detail: str = "") -> None:
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"[PASS] {name}")
    else:
        FAIL += 1
        suffix = f" -> {detail}" if detail else ""
        print(f"[FAIL] {name}{suffix}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def run_server_once(server, result: dict) -> None:
    try:
        result["receipt"] = server.serve_once()
    except Exception as exc:
        result["error"] = exc


print("=" * 72)
print("UBIN v1.0.4 PUBLIC-CONSUMER INTEGRATION TEST")
print("=" * 72)
print("Python:", sys.version.split()[0])
print("UBIN:", ubin.__version__)
print()

# ---------------------------------------------------------------------------
# 1. IMPORT / PACKAGE METADATA
# ---------------------------------------------------------------------------
print("1) IMPORT / PACKAGE")
check("import ubin", True)
check(
    "UBIN version is 1.0.4",
    ubin.__version__ == EXPECTED_VERSION,
    ubin.__version__,
)

try:
    installed_version = importlib.metadata.version("ubin")
except importlib.metadata.PackageNotFoundError:
    installed_version = None

check(
    "distribution metadata is installed",
    installed_version is not None,
    str(installed_version),
)
if installed_version is not None:
    check(
        "distribution metadata version matches",
        installed_version == EXPECTED_VERSION,
        installed_version,
    )

requirements = importlib.metadata.requires("ubin") or []
runtime_requirements = [
    req for req in requirements
    if "extra ==" not in req.lower()
]
check(
    "cryptography dependency is declared",
    any(req.lower().startswith("cryptography") for req in runtime_requirements),
    repr(runtime_requirements),
)
check(
    "NumPy is not a required UBIN runtime dependency",
    not any(req.lower().startswith("numpy") for req in runtime_requirements),
    repr(runtime_requirements),
)
print()

with tempfile.TemporaryDirectory(prefix="ubin-public-test-") as tmp_name:
    tmp = Path(tmp_name)

    # -----------------------------------------------------------------------
    # 2. UNIVERSAL FILE / MEMORY / STREAM ACCESS
    # -----------------------------------------------------------------------
    print("2) UNIVERSAL BINARY ACCESS")

    source = tmp / "anything.futureXYZ"
    payload = (
        b"UBIN handles the bytes. You handle the logic.\n"
        + bytes(range(256))
        + os.urandom(32 * 1024)
    )
    source.write_bytes(payload)
    expected_sha = hashlib.sha256(payload).hexdigest()

    with ubin.open(source) as obj:
        check("open unknown/custom extension", obj.size == len(payload))
        check("file name preserved", obj.name == source.name, obj.name)
        check(
            "unknown type falls back safely",
            isinstance(obj.type, str) and len(obj.type) > 0,
            obj.type,
        )
        check("read_at exact bytes", obj.read_at(0, 4) == payload[:4])
        check("hash SHA-256", obj.hash() == expected_sha)
        check("verify SHA-256", obj.verify(expected_sha))

        streamed = b"".join(obj.stream(block_size=4096))
        check("stream reconstructs exact payload", streamed == payload)

    with ubin.open(payload, name="memory.custom") as obj:
        check("open bytes", obj.bytes() == payload)
        check("bytes hash", obj.hash() == expected_sha)

    with ubin.open(bytearray(payload), name="buffer.custom") as obj:
        check("open bytearray", obj.read_at(10, 100) == payload[10:110])

    with ubin.open(memoryview(payload), name="view.custom") as obj:
        check("open memoryview", obj.size == len(payload))

    caller_stream = io.BytesIO(payload)
    with ubin.open(caller_stream, name="stream.custom") as obj:
        check("open seekable binary stream", obj.hash() == expected_sha)
    check(
        "caller-owned stream remains open",
        not caller_stream.closed,
    )
    caller_stream.close()
    print()

    # -----------------------------------------------------------------------
    # 3. LOCAL AUTHENTICATED SECURE CONTAINER
    # -----------------------------------------------------------------------
    print("3) LOCAL SECURE CONTAINER")

    secure_path = tmp / "payload.ubs"
    restored_path = tmp / "payload-restored.futureXYZ"

    secured = ubin.secure(source)
    secure_receipt = secured.save(
        secure_path,
        frame_size=4096,
    )
    restore_receipt = ubin.decrypt(
        secure_path,
        restored_path,
        key=secure_receipt.key,
    )

    check("secure container created", secure_path.is_file())
    check("local decrypt publishes output", restored_path.is_file())
    check(
        "local secure round-trip exact",
        restored_path.read_bytes() == payload,
    )
    check(
        "local SHA-256 exact",
        restore_receipt.sha256 == expected_sha,
        restore_receipt.sha256,
    )

    wrong_output = tmp / "wrong-key-output.bin"
    wrong_key_rejected = False
    try:
        ubin.decrypt(
            secure_path,
            wrong_output,
            key=os.urandom(32),
        )
    except ubin.UbinError:
        wrong_key_rejected = True
    check("wrong local key rejected", wrong_key_rejected)
    check(
        "wrong-key output not published",
        not wrong_output.exists(),
    )
    print()

    # -----------------------------------------------------------------------
    # 4. LOSSLESS AUTHENTICATED PNG CARRIER
    # -----------------------------------------------------------------------
    print("4) PNG IMAGE CARRIER")

    carrier = tmp / "payload.ubin.png"
    image_restored = tmp / "image-restored.futureXYZ"
    passphrase = "UBIN-public-test-long-private-passphrase-2026"

    image_receipt = ubin.to_image(
        source,
        carrier,
        passphrase=passphrase,
        frame_size=4096,
        krp_block_size=256,
        width=256,
    )
    image_restore = ubin.from_image(
        carrier,
        image_restored,
        passphrase=passphrase,
        krp_block_size=256,
    )

    check(
        "real PNG signature",
        carrier.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n",
    )
    check("carrier layout is KRP + PNG", image_receipt.layout == "krp+png")
    check(
        "image carrier exact restoration",
        image_restored.read_bytes() == payload,
    )
    check(
        "image carrier SHA-256 exact",
        image_restore.sha256 == expected_sha == image_receipt.sha256,
    )

    bad_image_output = tmp / "bad-passphrase-output.bin"
    wrong_passphrase_rejected = False
    try:
        ubin.from_image(
            carrier,
            bad_image_output,
            passphrase="definitely-the-wrong-passphrase",
            krp_block_size=256,
        )
    except ubin.UbinError:
        wrong_passphrase_rejected = True

    check("wrong image passphrase rejected", wrong_passphrase_rejected)
    check(
        "wrong-passphrase output not published",
        not bad_image_output.exists(),
    )
    print()

    # -----------------------------------------------------------------------
    # 5. TLS 1.3 + RESUME + KRP NETWORK TEST
    # -----------------------------------------------------------------------
    print("5) NETWORK / TLS / RESUME / KRP")

    network_source = tmp / "network.futureXYZ"
    network_frame_size = 64 * 1024
    network_payload = os.urandom(network_frame_size * 6 + 123)
    network_source.write_bytes(network_payload)

    cert = tmp / "localhost-cert.pem"
    key = tmp / "localhost-key.pem"
    received_dir = tmp / "received"
    client_state = tmp / "client-resume"

    generate_localhost_certificate(cert, key)

    # _interrupt_once_after_frames is an explicit test/demo hook shipped by
    # the reference SecureServer. It deliberately breaks the first connection
    # after three authenticated frames so the second connection must resume.
    server = SecureServer(
        host="127.0.0.1",
        port=0,
        certfile=cert,
        keyfile=key,
        output_dir=received_dir,
        _interrupt_once_after_frames=3,
    )

    first_result = {}
    first_thread = threading.Thread(
        target=run_server_once,
        args=(server, first_result),
        daemon=True,
    )
    first_thread.start()

    first_interrupted = False
    try:
        ubin.secure(network_source).send(
            "127.0.0.1",
            port=server.port,
            cafile=cert,
            frame_size=network_frame_size,
            resume=True,
            permutation=True,
            state_dir=client_state,
        )
    except Exception:
        first_interrupted = True

    first_thread.join(timeout=15)
    check("first network attempt deliberately interrupted", first_interrupted)
    check("first server thread stopped", not first_thread.is_alive())

    second_result = {}
    second_thread = threading.Thread(
        target=run_server_once,
        args=(server, second_result),
        daemon=True,
    )
    second_thread.start()

    network_receipt = ubin.secure(network_source).send(
        "127.0.0.1",
        port=server.port,
        cafile=cert,
        frame_size=network_frame_size,
        resume=True,
        permutation=True,
        state_dir=client_state,
    )

    second_thread.join(timeout=15)
    server.close()

    check("resumed server thread stopped", not second_thread.is_alive())
    if "error" in second_result:
        raise second_result["error"]

    received = received_dir / network_source.name
    receiver_receipt = second_result["receipt"]
    network_sha = sha256_file(network_source)

    check("TLS 1.3", network_receipt.tls_version == "TLSv1.3")
    check("KRP layout active", network_receipt.layout == "krp")
    check(
        "resume continued from frame 3",
        network_receipt.resumed_from_frame == 3,
        str(network_receipt.resumed_from_frame),
    )
    check(
        "resume did not resend all frames",
        network_receipt.frames_sent_this_attempt
        < network_receipt.frame_count,
    )
    check("received network file published", received.is_file())
    check(
        "network source/receiver bytes exact",
        received.read_bytes() == network_payload,
    )
    check(
        "sender and receiver SHA-256 exact",
        network_receipt.sha256
        == receiver_receipt.sha256
        == network_sha,
    )
    check(
        "network receipt exposes no AES key",
        not hasattr(network_receipt, "key"),
    )
    check(
        "network receipt exposes no KRP key",
        not hasattr(network_receipt, "permutation_key"),
    )
    check(
        "client resume state cleaned",
        not list(client_state.glob("*.json")),
    )
    print()

# ---------------------------------------------------------------------------
# 6. CLI SMOKE TEST
# ---------------------------------------------------------------------------
print("6) CLI")

cli = subprocess.run(
    [sys.executable, "-m", "ubin.cli", "--version"],
    capture_output=True,
    text=True,
)
check("CLI exits successfully", cli.returncode == 0, cli.stderr.strip())
check(
    "CLI reports UBIN 1.0.4",
    "1.0.4" in cli.stdout,
    cli.stdout.strip(),
)
print()

print("=" * 72)
print(f"RESULT: {PASS} passed, {FAIL} failed")
print("=" * 72)

if FAIL:
    raise SystemExit(1)

print("ALL PUBLIC-CONSUMER UBIN v1.0.4 INTEGRATION CHECKS PASSED.")
