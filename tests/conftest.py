"""Repository-wide pytest portability guards."""

import pytest


MAX_PYTEST_NODEID_LENGTH = 2048


def pytest_collection_modifyitems(items):
    """Reject pathological test IDs before they reach platform environment limits."""
    for item in items:
        nodeid = item.nodeid

        if len(nodeid) <= MAX_PYTEST_NODEID_LENGTH:
            continue

        preview = nodeid[:240]

        raise pytest.UsageError(
            "pytest node ID exceeds UBIN's portability limit: "
            f"{len(nodeid)} characters; "
            f"maximum is {MAX_PYTEST_NODEID_LENGTH}. "
            f"Add an explicit short parametrization id. "
            f"Node ID begins with: {preview!r}"
        )
