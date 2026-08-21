from __future__ import annotations

import statistics as _statistics


def mean(values): return _statistics.mean(values)
def median(values): return _statistics.median(values)
def variance(values): return _statistics.variance(values)
def pstdev(values): return _statistics.pstdev(values)

__all__ = ["mean", "median", "variance", "pstdev"]
