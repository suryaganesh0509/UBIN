from __future__ import annotations

import io
import json as std_json
import socket
from types import SimpleNamespace

import pytest
import ubin
from ubin.sdk import CapabilityManifest


def test_resource_path_stream_and_invalid_source(tmp_path):
    source = tmp_path / "resource.bin"
    source.write_bytes(b"abcdef")

    with ubin.resource(source) as resource:
        assert resource.name == source.name
        assert resource.size == 6
        assert resource.read(resource.size) == b"abcdef"
        assert resource.read_at(2, 2) == b"cd"
        assert b"".join(resource.stream(block_size=2)) == b"abcdef"
        digest = resource.hash()
        assert resource.verify(digest)
        assert resource.info().size == 6

    stream = io.BytesIO(b"stream-data")
    stream.name = "named-stream.bin"
    with ubin.resource(stream) as resource:
        assert resource.name == "named-stream.bin"
        assert resource.read_at(0, 6) == b"stream"

    with pytest.raises(TypeError):
        ubin.resource(object())


def test_pipeline_validation_overwrite_and_failure_cleanup(tmp_path, monkeypatch):
    with pytest.raises(ValueError):
        ubin.pipeline(b"x", block_size=0)

    pipe = ubin.pipeline(b"abc")
    with pytest.raises(TypeError):
        pipe.map_bytes("not-callable")

    target = tmp_path / "target.bin"
    target.write_bytes(b"old")
    with pytest.raises(FileExistsError):
        ubin.pipeline(b"new").write(target)

    assert ubin.pipeline(b"new").write(target, overwrite=True) == target
    assert target.read_bytes() == b"new"

    failing_target = tmp_path / "failure.bin"

    def fail_replace(_source, _destination):
        raise OSError("replace failed")

    monkeypatch.setattr("ubin._pipeline.os.replace", fail_replace)
    with pytest.raises(OSError, match="replace failed"):
        ubin.pipeline(b"abc").write(failing_target)

    assert not failing_target.exists()
    assert not list(tmp_path.glob(".*.ubin-part"))


def test_workflow_validation_branches():
    flow = ubin.flow()
    with pytest.raises(ValueError):
        flow.task("", lambda _: None)

    flow.task("a", lambda _: 1)
    with pytest.raises(ValueError):
        flow.task("a", lambda _: 2)

    with pytest.raises(ValueError):
        ubin.flow().task("self", lambda _: None, depends_on=("self",))

    unknown = ubin.flow()
    unknown.task("a", lambda _: None, depends_on=("missing",))
    with pytest.raises(ValueError, match="unknown dependencies"):
        unknown.run()


def test_catalog_load_resolve_and_file_integrity(tmp_path):
    payload = tmp_path / "provider.whl"
    payload.write_bytes(b"provider-bytes")

    import hashlib

    expected = hashlib.sha256(b"provider-bytes").hexdigest()
    catalog_path = tmp_path / "catalog.json"
    catalog_path.write_text(
        std_json.dumps(
            {
                "entries": [
                    {
                        "capability": "plot",
                        "package": "ubin-plot",
                        "version": "1.2.3",
                        "sha256": expected,
                        "trusted": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    entries = ubin.catalog.load(catalog_path)
    assert len(entries) == 1
    assert ubin.catalog.resolve(entries, "plot").package == "ubin-plot"
    assert ubin.catalog.verify_file(payload, expected.upper())
    assert not ubin.catalog.verify_file(payload, "0" * 64)

    with pytest.raises(ValueError):
        ubin.catalog.resolve(entries, "missing")

    duplicate = entries + entries
    with pytest.raises(ValueError):
        ubin.catalog.resolve(duplicate, "plot")


def test_catalog_ed25519_signature_verification():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    payload = b"UBIN catalog payload"
    signature = private_key.sign(payload)

    assert ubin.catalog.verify_signature(payload, signature, public_key)
    assert not ubin.catalog.verify_signature(payload + b"x", signature, public_key)
    assert not ubin.catalog.verify_signature(payload, signature, b"bad-key")


def test_csv_round_trip_overwrite_empty_and_cleanup(tmp_path, monkeypatch):
    path = tmp_path / "rows.csv"
    rows = [{"name": "a", "value": "1"}, {"name": "b", "value": "2"}]

    assert ubin.csv.write_rows(path, rows) == path
    assert ubin.csv.read_rows(path) == rows

    with pytest.raises(FileExistsError):
        ubin.csv.write_rows(path, rows)

    ubin.csv.write_rows(path, [{"name": "c", "value": "3"}], overwrite=True)
    assert ubin.csv.read_rows(path) == [{"name": "c", "value": "3"}]

    empty = tmp_path / "empty.csv"
    ubin.csv.write_rows(empty, [], fieldnames=["name", "value"])
    assert ubin.csv.read_rows(empty) == []

    failing = tmp_path / "failure.csv"

    def fail_replace(_source, _destination):
        raise OSError("replace failed")

    monkeypatch.setattr("ubin.csv.os.replace", fail_replace)
    with pytest.raises(OSError, match="replace failed"):
        ubin.csv.write_rows(failing, rows)

    assert not failing.exists()
    assert not list(tmp_path.glob(".*.ubin-part"))


def test_compress_file_round_trip_overwrite_and_cleanup(tmp_path, monkeypatch):
    source = tmp_path / "source.bin"
    source.write_bytes(b"UBIN" * 1024)
    target = tmp_path / "source.bin.gz"

    assert ubin.compress.gzip_file(source, target, block_size=31) == target
    assert ubin.compress.gunzip_bytes(target.read_bytes()) == source.read_bytes()

    with pytest.raises(FileExistsError):
        ubin.compress.gzip_file(source, target)

    ubin.compress.gzip_file(source, target, overwrite=True)
    assert ubin.compress.gunzip_bytes(target.read_bytes()) == source.read_bytes()

    failing = tmp_path / "failure.gz"

    def fail_replace(_source, _destination):
        raise OSError("replace failed")

    monkeypatch.setattr("ubin.compress.os.replace", fail_replace)
    with pytest.raises(OSError, match="replace failed"):
        ubin.compress.gzip_file(source, failing)

    assert not failing.exists()
    assert not list(tmp_path.glob(".*.ubin-part"))


def test_json_helpers_overwrite_and_cleanup(tmp_path, monkeypatch):
    assert ubin.json.loads('{"a":1}') == {"a": 1}
    assert ubin.json.loads(b'{"a":1}') == {"a": 1}
    assert ubin.json.dumps({"b": 2, "a": 1}) == '{"a":1,"b":2}'
    assert "\n" in ubin.json.dumps({"a": 1}, pretty=True)

    target = tmp_path / "value.json"
    ubin.json.write(target, {"a": 1})

    with pytest.raises(FileExistsError):
        ubin.json.write(target, {"a": 2})

    ubin.json.write(target, {"a": 2}, overwrite=True)
    assert ubin.json.read(target) == {"a": 2}

    failing = tmp_path / "failure.json"

    def fail_replace(_source, _destination):
        raise OSError("replace failed")

    monkeypatch.setattr("ubin.json.os.replace", fail_replace)
    with pytest.raises(OSError, match="replace failed"):
        ubin.json.write(failing, {"a": 1})

    assert not failing.exists()
    assert not list(tmp_path.glob(".*.ubin-part"))


def test_path_text_math_stats_and_system_helpers(tmp_path):
    nested = tmp_path / "a" / "b.txt"
    nested.parent.mkdir(parents=True)
    nested.write_bytes(b"12345")

    assert ubin.path.exists(nested)
    assert ubin.path.is_file(nested)
    assert ubin.path.size(nested) == 5
    assert ubin.path.walk(tmp_path) == (nested,)
    assert ubin.path.join(tmp_path, "a", "b.txt") == nested

    assert ubin.text.find("universal binary", "binary") == 10
    assert ubin.text.replace("a-b-a", "a", "x", 1) == "x-b-a"

    assert ubin.math.percentage(1, 4) == 25
    with pytest.raises(ValueError):
        ubin.math.clamp(1, 2, 1)
    with pytest.raises(ZeroDivisionError):
        ubin.math.percentage(1, 0)

    assert ubin.stats.variance([1, 2, 3]) == 1
    assert ubin.stats.pstdev([1, 1, 1]) == 0

    info = ubin.system.info()
    assert {"system", "release", "machine", "python", "cpu_count"} <= set(info)


def test_plot_file_output_validation_overwrite_and_cleanup(tmp_path, monkeypatch):
    output = tmp_path / "plot.svg"
    svg = ubin.plot.line([1, 1], [2, 2], width=128, height=128, output=output)
    assert output.read_text(encoding="utf-8") == svg

    with pytest.raises(FileExistsError):
        ubin.plot.line([0, 1], [0, 1], output=output)

    overwritten = ubin.plot.line(
        [0, 1],
        [1, 0],
        output=output,
        overwrite=True,
    )
    assert output.read_text(encoding="utf-8") == overwritten

    with pytest.raises(ValueError):
        ubin.plot.line([], [])
    with pytest.raises(ValueError):
        ubin.plot.line([1], [1, 2])
    with pytest.raises(ValueError):
        ubin.plot.line([1], [1], width=32)

    failing = tmp_path / "failure.svg"

    def fail_replace(_source, _destination):
        raise OSError("replace failed")

    monkeypatch.setattr("ubin.plot.os.replace", fail_replace)
    with pytest.raises(OSError, match="replace failed"):
        ubin.plot.line([0, 1], [0, 1], output=failing)

    assert not failing.exists()
    assert not list(tmp_path.glob(".*.ubin-part"))


def test_permission_manifest_mapping_and_validation():
    manifest = ubin.permissions.PermissionManifest.from_mapping(
        {
            "filesystem_read": 1,
            "network": True,
        }
    )
    assert manifest.filesystem_read
    assert manifest.network
    assert manifest.granted() == ("filesystem_read", "network")
    assert ubin.permissions.PermissionManifest.from_mapping(None).granted() == ()

    with pytest.raises(ValueError, match="unknown UBIN permission"):
        ubin.permissions.PermissionManifest.from_mapping({"root": True})


def test_sdk_validation_error_paths_and_provider_manifest():
    assert CapabilityManifest("demo", "1.0.0").supports("2.0.0")

    with pytest.raises(ValueError, match="invalid capability version"):
        CapabilityManifest("demo", "version").validate()

    with pytest.raises(ValueError, match="unsupported UBIN capability API"):
        CapabilityManifest("demo", "1.0.0", api_version="2").validate()

    with pytest.raises(ValueError, match="min_ubin"):
        CapabilityManifest(
            "demo",
            "1.0.0",
            min_ubin="2.0.0",
            max_ubin_exclusive="2.0.0",
        ).validate()

    with pytest.raises(ValueError, match="invalid UBIN version"):
        CapabilityManifest(
            "demo",
            "1.0.0",
            min_ubin="bad",
        ).validate()

    provider = SimpleNamespace(
        UBIN_CAPABILITY=CapabilityManifest("demo", "1.0.0")
    )
    assert ubin.sdk.manifest_from_provider(provider).name == "demo"

    with pytest.raises(TypeError):
        ubin.sdk.manifest_from_provider(object())


class _FakeDist:
    def __init__(self, name):
        self.name = name


class _FakeEntryPoint:
    def __init__(self, name, value, loaded, distribution="ubin-test-provider"):
        self.name = name
        self.value = value
        self._loaded = loaded
        self.dist = _FakeDist(distribution)

    def load(self):
        return self._loaded


def _provider_entry_points(entries):
    def entry_points(*, group, name=None):
        assert group == ubin.providers.ENTRY_POINT_GROUP
        selected = entries
        if name is not None:
            selected = [entry for entry in selected if entry.name == name]
        return tuple(selected)

    return entry_points


def test_provider_registry_listing_loading_conflicts_and_validation(monkeypatch):
    cloud_backend = object()
    process_backend = object()
    ui_backend = object()
    web_backend = object()

    entries = [
        _FakeEntryPoint("cloud.demo", "pkg.cloud:Provider", cloud_backend),
        _FakeEntryPoint("process.demo", "pkg.process:Provider", process_backend),
        _FakeEntryPoint("ui.demo", "pkg.ui:Provider", ui_backend),
        _FakeEntryPoint("web.demo", "pkg.web:Provider", web_backend),
        _FakeEntryPoint("invalid", "pkg:Invalid", object()),
        _FakeEntryPoint("cloud.bad-name", "pkg:Invalid", object()),
    ]
    monkeypatch.setattr(
        ubin.providers.metadata,
        "entry_points",
        _provider_entry_points(entries),
    )

    all_items = ubin.providers.list()
    assert {(item.family, item.name) for item in all_items} == {
        ("cloud", "demo"),
        ("process", "demo"),
        ("ui", "demo"),
        ("web", "demo"),
    }
    assert ubin.providers.list("cloud")[0].distribution == "ubin-test-provider"
    assert ubin.providers.load("cloud", "demo") is cloud_backend

    assert ubin.cloud.providers()[0].name == "demo"
    assert ubin.cloud.load("demo") is cloud_backend
    assert ubin.process.providers()[0].name == "demo"
    assert ubin.process.load("demo") is process_backend
    assert ubin.ui.providers()[0].name == "demo"
    assert ubin.ui.load("demo") is ui_backend
    assert ubin.web.providers()[0].name == "demo"
    assert ubin.web.load("demo") is web_backend

    with pytest.raises(ValueError):
        ubin.providers.list("Bad Family")
    with pytest.raises(ValueError):
        ubin.providers.load("cloud", "Bad Name")

    monkeypatch.setattr(
        ubin.providers.metadata,
        "entry_points",
        _provider_entry_points([]),
    )
    with pytest.raises(ubin.providers.ProviderRequired):
        ubin.providers.load("cloud", "missing")

    conflicts = [
        _FakeEntryPoint("cloud.demo", "a:Provider", object()),
        _FakeEntryPoint("cloud.demo", "b:Provider", object()),
    ]
    monkeypatch.setattr(
        ubin.providers.metadata,
        "entry_points",
        _provider_entry_points(conflicts),
    )
    with pytest.raises(ubin.providers.ProviderConflict):
        ubin.providers.load("cloud", "demo")


def test_runtime_builtin_and_provider_verification_branches(monkeypatch):
    runtime_module = ubin.runtime
    runtime = runtime_module.Runtime()

    assert runtime.capabilities(include_plugins=False)
    assert runtime.info("search").name == "search"
    assert runtime.load("search") is ubin.search

    builtin = runtime.verify("search")
    assert builtin.ok
    assert builtin.kind == "builtin"

    plugin_info = SimpleNamespace(
        name="hello",
        kind="plugin",
        provider="test:hello",
    )
    monkeypatch.setattr(
        runtime_module._capabilities,
        "get_capability_info",
        lambda _name: plugin_info,
    )

    discoverable = runtime.verify("hello", load_provider=False)
    assert discoverable.ok
    assert "discoverable" in discoverable.message

    compatible_provider = SimpleNamespace(
        UBIN_CAPABILITY=CapabilityManifest("hello", "1.0.0")
    )
    monkeypatch.setattr(
        runtime_module._capabilities,
        "load_capability",
        lambda _name: compatible_provider,
    )
    compatible = runtime.verify("hello", load_provider=True)
    assert compatible.ok
    assert compatible.manifest is not None

    wrong_name_provider = SimpleNamespace(
        UBIN_CAPABILITY=CapabilityManifest("other", "1.0.0")
    )
    monkeypatch.setattr(
        runtime_module._capabilities,
        "load_capability",
        lambda _name: wrong_name_provider,
    )
    mismatch = runtime.verify("hello", load_provider=True)
    assert not mismatch.ok
    assert "does not match" in mismatch.message

    incompatible_provider = SimpleNamespace(
        UBIN_CAPABILITY=CapabilityManifest(
            "hello",
            "1.0.0",
            min_ubin="3.0.0",
            max_ubin_exclusive="4.0.0",
        )
    )
    monkeypatch.setattr(
        runtime_module._capabilities,
        "load_capability",
        lambda _name: incompatible_provider,
    )
    incompatible = runtime.verify("hello", load_provider=True)
    assert not incompatible.ok
    assert "does not support" in incompatible.message

    monkeypatch.setattr(
        runtime_module._capabilities,
        "load_capability",
        lambda _name: object(),
    )
    invalid = runtime.verify("hello", load_provider=True)
    assert not invalid.ok
    assert "UBIN_CAPABILITY" in invalid.message


def test_diagnostics_deep_and_failure_branches(monkeypatch):
    import ubin.diagnostics as diagnostics

    report = diagnostics.doctor(deep=True)
    assert report.ubin_version == "2.0.0"
    assert report.healthy
    payload = report.as_dict()
    assert payload["healthy"]
    assert payload["checks"]

    class RegistryFailureRuntime:
        def capabilities(self):
            raise RuntimeError("registry failed")

    monkeypatch.setattr(diagnostics, "Runtime", RegistryFailureRuntime)
    failed_registry = diagnostics.doctor()
    registry_check = next(
        check
        for check in failed_registry.checks
        if check.name == "capability_registry"
    )
    assert not registry_check.ok
    assert "registry failed" in registry_check.detail

    class DeepFailureRuntime:
        def capabilities(self):
            return (SimpleNamespace(name="broken", kind="plugin"),)

        def verify(self, _name, *, load_provider=False):
            assert load_provider
            raise RuntimeError("verification failed")

    monkeypatch.setattr(diagnostics, "Runtime", DeepFailureRuntime)
    failed_deep = diagnostics.doctor(deep=True)
    deep_check = next(
        check
        for check in failed_deep.checks
        if check.name == "capability:broken"
    )
    assert not deep_check.ok
    assert "verification failed" in deep_check.detail


def test_environment_error_and_change_detection(tmp_path):
    config = tmp_path / "ubin.toml"
    lockfile = tmp_path / "ubin.lock"

    ubin.environment.init(config)
    with pytest.raises(FileExistsError):
        ubin.environment.init(config)

    ubin.environment.init(config, overwrite=True)

    bad_config = tmp_path / "bad.toml"
    bad_config.write_text(
        '[ubin]\nversion = "2.0.0"\n\n'
        '[capabilities]\ndefinitely_missing = "builtin"\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="not available"):
        ubin.environment.lock(bad_config, lockfile)

    ubin.environment.lock(config, lockfile)
    payload = std_json.loads(lockfile.read_text(encoding="utf-8"))
    capability_name = next(iter(payload["capabilities"]))
    payload["capabilities"][capability_name]["provider"] = "changed-provider"
    lockfile.write_text(std_json.dumps(payload), encoding="utf-8")

    result = ubin.environment.sync(lockfile)
    assert not result["ok"]
    assert capability_name in result["changed"]


def test_hash_verify_case_insensitive():
    expected = ubin.hash.digest(b"UBIN")
    assert ubin.hash.verify(b"UBIN", expected.upper())
    assert not ubin.hash.verify(b"other", expected)


def test_network_resolve_and_local_tcp_connect():
    addresses = ubin.net.resolve("127.0.0.1", 80)
    assert addresses

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.settimeout(2)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    client = ubin.net.tcp_connect("127.0.0.1", port, timeout=2)
    server, _address = listener.accept()
    try:
        client.sendall(b"UBIN")
        assert server.recv(4) == b"UBIN"
    finally:
        client.close()
        server.close()
        listener.close()
