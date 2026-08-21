from __future__ import annotations

from .providers import list as _list_providers, load as _load_provider

def providers():
    return _list_providers('ai')

def load(name: str):
    return _load_provider('ai', name)

__all__ = ["providers", "load"]
