# UBIN v1.0.6 — Universal Single-Import Foundation

## Objective

v1.0.6 establishes the architecture required for UBIN to grow from a binary/security package into a universal capability platform without turning `import ubin` into an eager monolith.

## Public model

```python
import ubin

ubin.open(...)
ubin.secure(...)
ubin.search.linear(...)
ubin.search.binary(...)
ubin.sort.values(...)
ubin.sort.merge(...)
ubin.sort.quick(...)
ubin.ds.Stack(...)
ubin.ds.Queue(...)
ubin.ds.BinaryTree(...)
ubin.ds.Graph(...)
```

Normal users do not import implementation modules.

## Tiny-core rule

Bare `import ubin` loads only the public facade, core binary objects, and error types. New capability modules (`search`, `sort`, `ds`) and the existing secure implementation are loaded only when first used.

Python's module-level `__getattr__` / `__dir__` mechanism is used for lazy public namespace resolution. The runtime caches resolved capabilities after first access.

## Capability provider rule

Built-in capability names map to bundled modules. Installed third-party or future UBIN-maintained capability distributions may register entry points in the group:

```text
ubin.capabilities
```

The core discovers metadata lazily. Provider code is not loaded merely because `import ubin` ran.

## Installation rule

v1.0.6 foundation does **not** silently run package installers from ordinary Python attribute access. Silent runtime downloads would harm reproducibility, offline behavior, security policy, CI, containers, and locked enterprise environments.

A later `ubin add <capability>` flow may install from a trusted/verified catalog after the provider model, signature policy, version resolution, and rollback behavior are specified and tested.

## Backward compatibility

The existing public calls remain:

- `ubin.open`
- `ubin.secure`
- `ubin.decrypt`
- `ubin.secure_server`
- `ubin.to_image`
- `ubin.from_image`

The cryptographic algorithms, container/wire formats, resume protocol, KRP format, and PNG carrier format are not intentionally modified by this facade foundation.

## First proof capabilities

### Search

- `ubin.search.linear`
- `ubin.search.binary`

### Sort

- `ubin.sort.values` — production default using Python's optimized stable sort
- `ubin.sort.merge` — explicit stable merge-sort implementation
- `ubin.sort.quick` — explicit iterative quicksort implementation

### Data structures

- `ubin.ds.Stack`
- `ubin.ds.Queue`
- `ubin.ds.BinarySearchTree`
- `ubin.ds.BinaryTree`
- `ubin.ds.Graph`

These are proof-of-architecture capabilities, not the intended boundary of UBIN.

## Required release gates

v1.0.6 must not be released until:

1. all existing v1.0.5 regression tests still pass;
2. new facade/capability tests pass;
3. bare import does not eagerly load `ubin.search`, `ubin.sort`, `ubin.ds`, or `ubin.secure`;
4. old top-level security calls still behave correctly after lazy loading;
5. import-time and memory measurements are recorded before/after;
6. coverage gate remains satisfied;
7. Ruff, Bandit, dependency audit, package checks, multi-OS CI, and public-consumer checks are green;
8. wheel/sdist and clean-install checks pass;
9. documentation and API examples match the actual release.

## Capability management

v1.0.6 also exposes `ubin list` / `ubin list --json` for capability discovery.
`ubin add NAME --package PACKAGE` is an explicit provider installation path.
Normal `import ubin` never installs packages. See `CAPABILITIES.md`.
