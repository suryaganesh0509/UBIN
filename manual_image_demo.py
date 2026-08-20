from pathlib import Path
import hashlib
import tempfile

import ubin


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while block := f.read(1024 * 1024):
            h.update(block)
    return h.hexdigest()


source = Path("sample.surya123")
passphrase = "UBIN-Final-Demo-2026"

with tempfile.TemporaryDirectory(prefix="ubin-v1-image-demo-") as tmp:
    tmp = Path(tmp)
    image = tmp / "sample.ubin.png"
    restored = tmp / "sample_restored.surya123"

    packed = ubin.to_image(source, image, passphrase=passphrase)
    unpacked = ubin.from_image(image, restored, passphrase=passphrase)

    print("PNG SIGNATURE:", image.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n")
    print("CARRIER:", image)
    print("DIMENSIONS:", f"{packed.width}x{packed.height}")
    print("ORIGINAL SIZE:", packed.original_size)
    print("CARRIER SIZE:", packed.carrier_size)
    print("LAYOUT:", packed.layout)
    print("Original SHA-256:", packed.sha256)
    print("Restored SHA-256:", unpacked.sha256)
    print("MATCH:", sha256(source) == sha256(restored) == packed.sha256)
