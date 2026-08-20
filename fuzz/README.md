# UBIN fuzzing

UBIN v1.0.1 ships two coverage-guided Atheris harnesses plus Hypothesis property tests.

## Targets

- `fuzz_krp.py` — KRP permutation/restoration invariants: exact bytes and exact length.
- `fuzz_png_parser.py` — malformed/truncated/arbitrary PNG carrier parser input; rejection must fail closed and never publish output.

## Local Linux run

```bash
python -m pip install -e ".[dev,fuzz]"
python fuzz/fuzz_krp.py -runs=10000 -max_len=8192
python fuzz/fuzz_png_parser.py -runs=5000 -max_len=8192
```

The scheduled GitHub Actions fuzz job is intentionally a bounded smoke run. Longer campaigns should be run separately or integrated with OSS-Fuzz. Automated fuzzing is useful evidence, but it is **not** a substitute for an independent professional security audit.
