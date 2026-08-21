from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Callable, Mapping

TaskFunction = Callable[[Mapping[str, Any]], Any]


@dataclass(frozen=True, slots=True)
class Task:
    name: str
    function: TaskFunction
    depends_on: tuple[str, ...] = ()


class Flow:
    def __init__(self):
        self._tasks: dict[str, Task] = {}

    def task(self, name: str, function: TaskFunction, *, depends_on=()) -> "Flow":
        if not name or name in self._tasks:
            raise ValueError(f"invalid or duplicate task name: {name!r}")
        dependencies = tuple(depends_on)
        if name in dependencies:
            raise ValueError("task cannot depend on itself")
        self._tasks[name] = Task(name, function, dependencies)
        return self

    def _layers(self) -> list[list[Task]]:
        remaining = dict(self._tasks)
        completed: set[str] = set()
        layers: list[list[Task]] = []
        while remaining:
            missing = {
                dep
                for task in remaining.values()
                for dep in task.depends_on
                if dep not in self._tasks
            }
            if missing:
                raise ValueError(f"workflow has unknown dependencies: {sorted(missing)!r}")
            ready = [task for task in remaining.values() if set(task.depends_on) <= completed]
            if not ready:
                raise ValueError("workflow dependency cycle detected")
            ready.sort(key=lambda task: task.name)
            layers.append(ready)
            for task in ready:
                completed.add(task.name)
                del remaining[task.name]
        return layers

    def run(self, *, parallel: bool = False, max_workers: int | None = None) -> dict[str, Any]:
        results: dict[str, Any] = {}
        for layer in self._layers():
            if parallel and len(layer) > 1:
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = {
                        task.name: executor.submit(task.function, {dep: results[dep] for dep in task.depends_on})
                        for task in layer
                    }
                    for name in sorted(futures):
                        results[name] = futures[name].result()
            else:
                for task in layer:
                    inputs = {dep: results[dep] for dep in task.depends_on}
                    results[task.name] = task.function(inputs)
        return results


def flow() -> Flow:
    return Flow()


__all__ = ["Task", "Flow", "flow"]
