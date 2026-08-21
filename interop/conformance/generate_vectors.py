from __future__ import annotations

import json
from pathlib import Path

import ubin


def main() -> None:
    target = Path(__file__).with_name("vectors.json")
    target.write_text(json.dumps(ubin.protocol.conformance_vector(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(target)


if __name__ == "__main__":
    main()
