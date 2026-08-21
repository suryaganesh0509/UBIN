from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest
import ubin
from ubin.sdk import CapabilityManifest


PROJECT = Path(__file__).resolve().parents[1]


def _run_fresh_python(code: str) -> str:
    env = dict(os.environ)
    existing = env.get("PYTHONPATH")
    local_src = str(PROJECT / "src")
    env["PYTHONPATH"] = local_src if not existing else local_src + os.pathsep + existing
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=PROJECT,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, (
        f"fresh interpreter failed\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
    )
    return result.stdout.strip()


def test_version_and_lazy_security():
    output = _run_fresh_python(
        "import sys\n"
        "import ubin\n"
        "def crypto_loaded():\n"
        "    return any(n == 'cryptography' or n.startswith('cryptography.') for n in sys.modules)\n"
        "assert ubin.__version__ == '1.0.7'\n"
        "assert 'ubin.secure' not in sys.modules\n"
        "assert not crypto_loaded()\n"
        "print('PASS')\n"
    )
    assert output == "PASS"


def test_expanded_capability_discovery_is_lazy():
    output = _run_fresh_python(
        "import sys\n"
        "import ubin\n"
        "def crypto_loaded():\n"
        "    return any(n == 'cryptography' or n.startswith('cryptography.') for n in sys.modules)\n"
        "names = {item.name for item in ubin.capabilities()}\n"
        "required = {'search', 'sort', 'ds', 'secure', 'runtime', 'sdk', 'protocol', 'environment', 'plot', 'data'}\n"
        "assert required <= names\n"
        "assert 'ubin.secure' not in sys.modules\n"
        "assert not crypto_loaded()\n"
        "print('PASS')\n"
    )
    assert output == "PASS"


def test_builtin_verification_without_loading_security():
    output = _run_fresh_python(
        "import sys\n"
        "import ubin\n"
        "def crypto_loaded():\n"
        "    return any(n == 'cryptography' or n.startswith('cryptography.') for n in sys.modules)\n"
        "result = ubin.verify_capability('secure')\n"
        "assert result.ok\n"
        "assert result.kind == 'builtin'\n"
        "assert 'ubin.secure' not in sys.modules\n"
        "assert not crypto_loaded()\n"
        "print('PASS')\n"
    )
    assert output == "PASS"


def test_resource_memory():
    with ubin.resource(b"abcdef", name="packet.bin") as obj:
        assert obj.size == 6
        assert obj.read_at(1, 3) == b"bcd"
        assert len(obj.hash()) == 64


def test_pipeline_transform_and_atomic_write(tmp_path):
    source = tmp_path / "source.bin"
    target = tmp_path / "target.bin"
    source.write_bytes(b"abcdef")
    result = ubin.pipeline(source, block_size=2).map_bytes(bytes.upper).write(target)
    assert result == target
    assert target.read_bytes() == b"ABCDEF"


def test_pipeline_stage_must_return_bytes(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"abc")
    pipe = ubin.pipeline(source).map_bytes(lambda chunk: "bad")
    with pytest.raises(TypeError):
        list(pipe.chunks())


def test_pipeline_digest(tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"abc")
    assert ubin.pipeline(source).digest() == ubin.hash.digest(source)


def test_flow_dependencies():
    flow = ubin.flow()
    flow.task("a", lambda _: 2)
    flow.task("b", lambda deps: deps["a"] * 3, depends_on=("a",))
    assert flow.run() == {"a": 2, "b": 6}


def test_flow_parallel_layer():
    flow = ubin.flow()
    flow.task("a", lambda _: 1)
    flow.task("b", lambda _: 2)
    flow.task("c", lambda deps: deps["a"] + deps["b"], depends_on=("a", "b"))
    assert flow.run(parallel=True)["c"] == 3


def test_flow_cycle_rejected():
    flow = ubin.flow()
    flow.task("a", lambda _: None, depends_on=("b",))
    flow.task("b", lambda _: None, depends_on=("a",))
    with pytest.raises(ValueError):
        flow.run()


def test_environment_init_lock_sync(tmp_path):
    config = tmp_path / "ubin.toml"
    lockfile = tmp_path / "ubin.lock"
    ubin.environment.init(config)
    payload = ubin.environment.read_config(config)
    assert payload["ubin"]["version"] == "1.0.7"
    ubin.environment.lock(config, lockfile)
    locked = json.loads(lockfile.read_text())
    assert locked["ubin"] == "1.0.7"
    assert ubin.environment.sync(lockfile)["ok"]


def test_sdk_manifest_validation():
    manifest = CapabilityManifest("hello", "1.2.3")
    assert manifest.validate() is manifest
    assert manifest.supports("1.0.7")
    assert not manifest.supports("2.0.0")


def test_sdk_rejects_invalid_name():
    with pytest.raises(ValueError):
        CapabilityManifest("Bad Name", "1.0.0").validate()


def test_permissions():
    assert "network" in ubin.permissions.for_capability("secure").granted()
    assert ubin.permissions.for_capability("sort").granted() == ()


def test_text_json_data_helpers(tmp_path):
    assert ubin.text.decode(ubin.text.encode("UBIN")) == "UBIN"
    path = tmp_path / "value.json"
    ubin.json.write(path, {"b": 2, "a": 1})
    assert ubin.json.read(path) == {"a": 1, "b": 2}
    table = ubin.data.table([{"a": 1, "b": 2}, {"a": 3, "b": 4}])
    assert table.select("a").column("a") == [1, 3]
    assert len(table.where(lambda row: row["a"] > 1)) == 1


def test_compress_round_trip():
    data = b"UBIN" * 100
    assert ubin.compress.gunzip_bytes(ubin.compress.gzip_bytes(data)) == data


def test_math_stats_helpers():
    assert ubin.math.clamp(9, 0, 5) == 5
    assert ubin.math.lerp(0, 10, 0.5) == 5
    assert ubin.stats.mean([1, 2, 3]) == 2
    assert ubin.stats.median([1, 2, 9]) == 2


def test_plot_svg():
    svg = ubin.plot.line([0, 1, 2], [2, 1, 4])
    assert svg.startswith("<svg")
    assert "polyline" in svg


def test_sqlite_helpers(tmp_path):
    connection = ubin.db.connect(tmp_path / "db.sqlite3")
    try:
        ubin.db.execute(connection, "create table values_table (value integer)")
        ubin.db.execute(connection, "insert into values_table(value) values (?)", (7,))
        assert ubin.db.query(connection, "select value from values_table") == [(7,)]
    finally:
        connection.close()


def test_parallel_helper():
    assert ubin.run.parallel(lambda value: value * 2, [1, 2, 3]) == [2, 4, 6]


def test_concurrent_helper():
    async def plus_one(value):
        await asyncio.sleep(0)
        return value + 1
    assert asyncio.run(ubin.run.concurrent(plus_one, [1, 2])) == [2, 3]


def test_provider_gateways_are_explicit():
    assert isinstance(ubin.ai.providers(), tuple)
    with pytest.raises(ubin.providers.ProviderRequired):
        ubin.ai.load("definitely_missing")
    with pytest.raises(ubin.providers.ProviderRequired):
        ubin.web.load("definitely_missing")


def test_doctor_shallow_does_not_load_security():
    output = _run_fresh_python(
        "import sys\n"
        "import ubin\n"
        "def crypto_loaded():\n"
        "    return any(n == 'cryptography' or n.startswith('cryptography.') for n in sys.modules)\n"
        "report = ubin.doctor()\n"
        "assert report.ubin_version == '1.0.7'\n"
        "assert report.healthy\n"
        "assert 'ubin.secure' not in sys.modules\n"
        "assert not crypto_loaded()\n"
        "print('PASS')\n"
    )
    assert output == "PASS"
