from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest

import ubin


def test_v107_single_import_namespaces_are_discoverable():
    assert ubin.__version__ == "1.0.7"
    public = dir(ubin)
    for name in ("search", "sort", "ds", "capabilities", "load"):
        assert name in public


def test_capability_modules_are_lazy_before_first_access():
    project = Path(__file__).resolve().parents[1]
    code = """
import sys
import ubin
for name in ('ubin.search', 'ubin.sort', 'ubin.ds', 'ubin.secure'):
    assert name not in sys.modules, (name, sorted(k for k in sys.modules if k.startswith('ubin')))

assert not any(
    name == 'cryptography' or name.startswith('cryptography.')
    for name in sys.modules
), 'bare import ubin must not eagerly load cryptography'

print('PASS')
"""
    env = dict(__import__("os").environ)
    env["PYTHONPATH"] = str(project / "src")
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=project,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "PASS"


def test_search_from_single_import():
    values = [2, 4, 6, 8, 10]
    assert ubin.search.linear(values, 6) == 2
    assert ubin.search.linear(values, 7) == -1
    assert ubin.search.binary(values, 8) == 3
    assert ubin.search.binary(values, 7) == -1


def test_binary_search_bounds():
    with pytest.raises(ValueError):
        ubin.search.binary([1, 2, 3], 2, lo=-1)
    with pytest.raises(ValueError):
        ubin.search.binary([1, 2, 3], 2, lo=2, hi=1)


def test_sort_from_single_import():
    values = [5, 1, 4, 2, 3, 3]
    expected = sorted(values)
    assert ubin.sort.values(values) == expected
    assert ubin.sort.merge(values) == expected
    assert ubin.sort.quick(values) == expected
    assert ubin.sort.values(values, reverse=True) == sorted(values, reverse=True)
    assert ubin.sort.merge(values, reverse=True) == sorted(values, reverse=True)
    assert ubin.sort.quick(values, reverse=True) == sorted(values, reverse=True)


def test_sort_key_support():
    values = ["bbb", "a", "cc"]
    expected = ["a", "cc", "bbb"]
    assert ubin.sort.values(values, key=len) == expected
    assert ubin.sort.merge(values, key=len) == expected
    assert ubin.sort.quick(values, key=len) == expected


def test_stack_queue_tree_graph_from_single_import():
    stack = ubin.ds.Stack([1, 2])
    stack.push(3)
    assert stack.peek() == 3
    assert stack.pop() == 3
    assert list(stack) == [1, 2]

    queue = ubin.ds.Queue([1, 2])
    queue.enqueue(3)
    assert queue.peek() == 1
    assert queue.dequeue() == 1
    assert list(queue) == [2, 3]

    tree = ubin.ds.BinaryTree([5, 3, 7, 4])
    assert 4 in tree
    assert 9 not in tree
    assert tree.inorder() == [3, 4, 5, 7]

    graph = ubin.ds.Graph()
    graph.add_edge("a", "b")
    graph.add_edge("a", "c")
    graph.add_edge("b", "d")
    assert graph.neighbors("a") == ("b", "c")
    assert graph.bfs("a") == ["a", "b", "c", "d"]
    assert graph.dfs("a") == ["a", "b", "d", "c"]


def test_capability_registry_lists_builtins():
    info = {item.name: item for item in ubin.capabilities(include_plugins=False)}
    assert {"search", "sort", "ds", "secure"} <= set(info)
    assert all(item.kind == "builtin" for item in info.values())


def test_load_capability():
    assert ubin.load("search") is ubin.search


def test_unknown_capability_is_attribute_error():
    with pytest.raises(AttributeError):
        getattr(ubin, "definitely_not_a_ubin_capability")


def test_secure_callable_survives_lazy_secure_package_import(tmp_path: Path):
    source = tmp_path / "sample.bin"
    source.write_bytes(b"single-import compatibility")
    assert callable(ubin.secure)
    wrapped = ubin.secure(source)
    assert wrapped is not None
    assert callable(ubin.secure)


def test_legacy_secure_submodule_import_keeps_ubin_secure_callable():
    project = Path(__file__).resolve().parents[1]
    code = """
import inspect
import ubin
from ubin.secure import SecureServer, generate_localhost_certificate
assert SecureServer is not None
assert callable(generate_localhost_certificate)
assert callable(ubin.secure), ubin.secure
assert str(inspect.signature(ubin.secure)) == '(source, *, key=None)'
print('PASS')
"""
    env = dict(__import__("os").environ)
    env["PYTHONPATH"] = str(project / "src")
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=project,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "PASS"
