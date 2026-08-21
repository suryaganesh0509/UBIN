from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor


def parallel(function, items, *, max_workers=None):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        return list(executor.map(function, items))


async def concurrent(function, items):
    tasks = [asyncio.create_task(function(item)) for item in items]
    return await asyncio.gather(*tasks)

__all__ = ["parallel", "concurrent"]
