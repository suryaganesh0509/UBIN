# UBIN Documentation — v2.0.0
- [`V2_0_0_STABLE.md`](V2_0_0_STABLE.md) — recommended stable v2 architecture and release contract
- [`PROTOCOL_V2.md`](PROTOCOL_V2.md) — frozen polyglot wire specification
- [`MIGRATION_V2.md`](MIGRATION_V2.md) — upgrade/compatibility guidance from v1

This directory is the detailed documentation for UBIN. The root `README.md` is intentionally short enough to act as the GitHub front door.

## Choose your path

- [`CAPABILITIES.md`](CAPABILITIES.md) — capability discovery, providers, and safe installation

- [`UBIN_VISION.md`](UBIN_VISION.md) — long-term universal-platform vision
- [`V1_0_6_UNIVERSAL_FACADE.md`](V1_0_6_UNIVERSAL_FACADE.md) — v1.0.6 single-import architecture

### I just want to use UBIN

1. [`GETTING_STARTED.md`](GETTING_STARTED.md)
2. [`USER_GUIDE.md`](USER_GUIDE.md)
3. [`API.md`](API.md)

### I want to understand how UBIN works

1. [`HOW_UBIN_WORKS.md`](HOW_UBIN_WORKS.md)
2. [`ARCHITECTURE.md`](ARCHITECTURE.md)
3. [`COMPLEXITY_AND_PERFORMANCE.md`](COMPLEXITY_AND_PERFORMANCE.md)
4. [`SECURITY.md`](SECURITY.md)
5. [`DESIGN_DECISIONS.md`](DESIGN_DECISIONS.md)

### I want to validate or contribute

1. [`TESTING.md`](TESTING.md)
2. [`../CONTRIBUTING.md`](../CONTRIBUTING.md)
3. [`RELEASING.md`](RELEASING.md)

### Something is not working

1. [`TROUBLESHOOTING.md`](TROUBLESHOOTING.md)
2. [`FAQ.md`](FAQ.md)

## v1.0.5 documentation contract

v1.0.5 is documentation-focused. Unless explicitly stated otherwise, its runtime semantics are the v1.0.4 stable runtime semantics.

There are no intentional v1.0.5 changes to:

- the top-level public operations
- AES-256-GCM behavior
- TLS 1.3 transport behavior
- X25519/HKDF session derivation
- local `.ubs` format
- network wire format
- resume format
- KRP format
- PNG carrier format

The purpose of v1.0.5 is to make the existing system understandable, reproducible, and easier to adopt.
