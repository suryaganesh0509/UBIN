from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys


def _run(project: Path, *args: str):
    env = os.environ.copy()
    env["PYTHONPATH"] = str(project / "src")
    return subprocess.run(
        [sys.executable, "-m", "ubin.cli", *args],
        cwd=project,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_cli_list_capabilities_json_does_not_load_secure():
    project = Path(__file__).resolve().parents[1]
    result = _run(project, "list", "--json")
    assert result.returncode == 0, result.stderr
    rows = json.loads(result.stdout)
    by_name = {row["name"]: row for row in rows}
    assert {"ds", "search", "secure", "sort"} <= set(by_name)
    assert by_name["secure"]["kind"] == "builtin"
    assert by_name["secure"]["loaded"] is False


def test_cli_list_capabilities_text():
    project = Path(__file__).resolve().parents[1]
    result = _run(project, "list")
    assert result.returncode == 0, result.stderr
    assert "CAPABILITY" in result.stdout
    for name in ("ds", "search", "secure", "sort"):
        assert name in result.stdout


def test_cli_add_builtin_is_safe_noop():
    project = Path(__file__).resolve().parents[1]
    result = _run(project, "add", "search")
    assert result.returncode == 0, result.stderr
    assert "already bundled" in result.stdout.lower()


def test_cli_add_unknown_requires_explicit_provider():
    project = Path(__file__).resolve().parents[1]
    result = _run(project, "add", "definitely_missing_ubin_capability")
    assert result.returncode == 2
    assert "--package" in result.stderr


def test_cli_add_rejects_option_like_package_spec():
    project = Path(__file__).resolve().parents[1]
    result = _run(
        project,
        "add",
        "definitely_missing_ubin_capability",
        "--package=-r",
    )
    assert result.returncode == 2
    assert "must not begin with '-'" in result.stderr
