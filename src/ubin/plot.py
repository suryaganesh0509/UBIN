from __future__ import annotations

import os
from pathlib import Path
import tempfile


def line(x, y, *, width=800, height=450, output=None, overwrite=False):
    xs, ys = list(x), list(y)
    if len(xs) != len(ys) or not xs:
        raise ValueError("x and y must be non-empty and have the same length")
    if width < 64 or height < 64:
        raise ValueError("plot dimensions are too small")
    xmin, xmax = min(xs), max(xs)
    ymin, ymax = min(ys), max(ys)
    xspan = xmax - xmin or 1
    yspan = ymax - ymin or 1
    margin = 32
    points = []
    for xv, yv in zip(xs, ys):
        px = margin + ((xv - xmin) / xspan) * (width - margin * 2)
        py = height - margin - ((yv - ymin) / yspan) * (height - margin * 2)
        points.append(f"{px:.2f},{py:.2f}")
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">'
        f'<polyline fill="none" stroke="currentColor" stroke-width="2" points="{" ".join(points)}"/>'
        '</svg>'
    )
    if output is not None:
        target = Path(output)
        if target.exists() and not overwrite:
            raise FileExistsError(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".ubin-part", dir=target.parent)
        temp = Path(temp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(svg)
                handle.flush()
                os.fsync(handle.fileno())
            if target.exists() and not overwrite:
                raise FileExistsError(target)
            os.replace(temp, target)
        except Exception:
            temp.unlink(missing_ok=True)
            raise
    return svg

__all__ = ["line"]
