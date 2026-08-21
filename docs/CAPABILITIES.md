# UBIN capability management

UBIN v1.0.6 establishes the first capability-management contract behind the
single-import platform.

## User model

Python code keeps one normal import:

```python
import ubin
```

Built-in capabilities are discovered without importing their implementation:

```python
ubin.capabilities()
```

A capability can be explicitly loaded:

```python
search = ubin.load("search")
```

The command line exposes the same platform view:

```bash
ubin list
ubin list --json
```

## Adding providers

UBIN does **not** silently download packages during normal application
execution. Silent package installation would make builds, CI, offline systems,
security review, and dependency locking harder to reason about.

If a future capability provider is not bundled, an explicit provider package
can be installed with:

```bash
ubin add <capability> --package <provider-package>
```

UBIN invokes pip in the current Python environment and then verifies that the
installed distribution registered the requested capability.

The provider package must register an entry point in the group:

```toml
[project.entry-points."ubin.capabilities"]
plot = "some_provider:api"
```

After installation, user code still uses only:

```python
import ubin
ubin.plot...
```

## Security model

`ubin add` is an explicit administrative action. Bare `import ubin`, normal
attribute access, and `ubin.load(...)` do not install software.

Future automatic acquisition, if added, must be opt-in and must use a trusted
UBIN capability catalogue rather than guessing arbitrary package names.
