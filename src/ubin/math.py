from __future__ import annotations

def clamp(value, minimum, maximum):
    if minimum > maximum:
        raise ValueError("minimum must not exceed maximum")
    return min(maximum, max(minimum, value))

def lerp(start, end, amount):
    return start + (end - start) * amount

def percentage(part, whole):
    if whole == 0:
        raise ZeroDivisionError("whole must not be zero")
    return (part / whole) * 100

__all__ = ["clamp", "lerp", "percentage"]
