#!/usr/bin/env python3
"""Coverage-guided Atheris harness for the UBIN lossless PNG parser."""
from __future__ import annotations

from pathlib import Path
import sys
import tempfile

import atheris

with atheris.instrument_imports():
    from ubin.errors import UbinCarrierError
    from ubin.secure.png_codec import decode_png_to_file


def TestOneInput(data: bytes) -> None:
    # Keep this harness intentionally small. Any parser rejection is expected;
    # crashes, assertion failures, hangs, or unexpected exceptions are bugs.
    with tempfile.TemporaryDirectory(prefix="ubin-png-fuzz-") as tmp:
        tmp = Path(tmp)
        candidate = tmp / "fuzz.png"
        output = tmp / "pixels.bin"
        candidate.write_bytes(data)
        try:
            decode_png_to_file(candidate, output)
        except UbinCarrierError:
            if output.exists():
                raise RuntimeError("rejected PNG published output")


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
