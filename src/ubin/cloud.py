from __future__ import annotations

from .providers import list as _list_providers, load as _load_provider

def providers():
    return _list_providers('cloud')

def load(name: str):
    return _load_provider('cloud', name)

__all__ = ["providers", "load"]
