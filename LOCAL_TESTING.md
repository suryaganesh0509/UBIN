# UBIN v1.0.7 local validation

Apply only to a clean repository whose current runtime is v1.0.6. Do not tag or push v1.0.7 until every gate is green.

```bash
cd /Users/suryag/Downloads/UBIN
source .venv/bin/activate
python /path/to/UBIN_v1.0.7_runtime_candidate_patch/apply_v1_0_7.py /Users/suryag/Downloads/UBIN
```

First inspect:

```bash
git diff --check
git status --short
git --no-pager diff --stat
python -c "import ubin; print(ubin.__version__)"
ubin --version
```

Expected version: `1.0.7`.

Run focused candidate tests:

```bash
pytest -q tests/test_v107_protocol.py tests/test_v107_runtime.py
```

Run the complete repository suite and coverage gate:

```bash
pytest -q
pytest -q --cov=ubin --cov-report=term-missing --cov-fail-under=82
```

Quality/security gates:

```bash
ruff check src tests fuzz benchmarks
bandit -r src/ubin -ll -ii
pip-audit
semgrep scan --config auto --error src/ubin
```

Public consumer compatibility:

```bash
python examples/public_consumer_test.py
```

Tiny import check:

```bash
python - <<'PY'
import sys
import ubin
assert ubin.__version__ == "1.0.7"
assert "ubin.secure" not in sys.modules
assert not any(n == "cryptography" or n.startswith("cryptography.") for n in sys.modules)
assert ubin.search.binary([1,3,5,7], 5) == 2
print("PASS: v1.0.7 Tiny UBIN")
PY
```

Protocol check:

```bash
python - <<'PY'
import ubin
v = ubin.protocol.conformance_vector()
print(v)
assert v["envelope_hex"] == "55424e32020100000000000a68656c6c6f205542494e"
print("PASS: Python v2-draft vector")
PY
```

C / C++ / Java preview:

```bash
rm -rf /tmp/ubin-v107-interop && mkdir -p /tmp/ubin-v107-interop/c /tmp/ubin-v107-interop/cpp /tmp/ubin-v107-interop/java
cc -std=c11 -Wall -Wextra -Werror interop/c/ubin_wire.c interop/c/test_vector.c -o /tmp/ubin-v107-interop/c/test
/tmp/ubin-v107-interop/c/test
c++ -std=c++17 -Wall -Wextra -Werror interop/cpp/test_vector.cpp -o /tmp/ubin-v107-interop/cpp/test
/tmp/ubin-v107-interop/cpp/test
javac -d /tmp/ubin-v107-interop/java interop/java/io/ubin/UbinWire.java interop/java/io/ubin/ProtocolSelfTest.java
java -cp /tmp/ubin-v107-interop/java io.ubin.ProtocolSelfTest
```

Finally build packages and test a clean wheel exactly as in the v1.0.6 release process. **Do not perform Git/tag/release actions yet.**
