"""Measure UBIN's in-process import cost for before/after comparisons."""
from __future__ import annotations

import json
import sys
import time
import tracemalloc

before_modules = set(sys.modules)
tracemalloc.start()
start = time.perf_counter()
import ubin  # noqa: E402
elapsed = time.perf_counter() - start
current, peak = tracemalloc.get_traced_memory()
tracemalloc.stop()

new_modules = sorted(set(sys.modules) - before_modules)
print(json.dumps({
    "ubin_version": ubin.__version__,
    "import_seconds": elapsed,
    "traced_current_bytes": current,
    "traced_peak_bytes": peak,
    "new_module_count": len(new_modules),
    "secure_loaded": "ubin.secure" in sys.modules,
    "cryptography_loaded": any(name == "cryptography" or name.startswith("cryptography.") for name in sys.modules),
    "capability_modules_loaded": [
        name for name in ("ubin.search", "ubin.sort", "ubin.ds") if name in sys.modules
    ],
}, indent=2, sort_keys=True))
