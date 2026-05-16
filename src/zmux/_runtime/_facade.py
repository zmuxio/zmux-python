"""Helpers for runtime facade modules that re-export split implementations."""

from __future__ import annotations


def export_modules(target_globals: dict, *modules: object) -> tuple[str, ...]:
    exported = []
    for module in modules:
        names = tuple(vars(module).get("__all__", ()))
        for name in names:
            target_globals[name] = getattr(module, name)
        exported.extend(names)
    return tuple(exported)
