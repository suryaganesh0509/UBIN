# UBIN v1.0.7 — Universal Runtime Candidate

UBIN v1.0.7 consolidates the pre-2.0 runtime work into one release candidate. It keeps the stable v1 binary/security APIs while adding a capability SDK/runtime, diagnostics, provider permissions, reproducible project metadata, resources, bounded-memory byte pipelines, workflows, lightweight capability namespaces, and a language-neutral protocol draft.

## Release boundary

v1.0.7 is the Python reference runtime and interoperability proving ground. It does **not** claim that C, C++, Java, and Python are already API-identical. The `interop/` implementations prove the common envelope framing and are used to evolve the v2 contract before it is frozen.

## Core principles

- One normal `import ubin`.
- Bare import remains lazy.
- Built-in capability import targets remain explicit literal allowlists.
- Unknown file format remains valid binary input.
- Full-file work is O(n); streaming memory stays bounded where feasible.
- No silent provider installation.
- Provider permissions are explicit metadata.
- Heavy ecosystems are providers/adapters rather than mandatory core dependencies.
- Existing v1 security/container/network/resume/KRP/PNG behavior is preserved.

## New runtime concepts

`ubin.resource`, `ubin.pipeline`, `ubin.flow`, `ubin.doctor`, `ubin.runtime`, `ubin.sdk`, `ubin.environment`, `ubin.protocol`, `ubin.catalog`, and expanded lightweight capability namespaces.

## v2 target

The v2 stable gate requires Python/C/C++/Java implementations to agree byte-for-byte on the final canonical representation, framing, errors, limits, streaming semantics, and secure profile.
