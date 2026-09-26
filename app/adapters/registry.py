from __future__ import annotations

from app.adapters.base import ToolAdapter
from app.adapters.sherlock import SherlockAdapter

_ADAPTERS: dict[str, ToolAdapter] = {}


def register(adapter: ToolAdapter) -> None:
    _ADAPTERS[adapter.name] = adapter


def unregister(name: str) -> None:
    _ADAPTERS.pop(name, None)


def get_adapter(name: str) -> ToolAdapter | None:
    return _ADAPTERS.get(name)


def all_adapters() -> list[ToolAdapter]:
    return sorted(_ADAPTERS.values(), key=lambda a: a.name)


def adapters_for(target_type: str) -> list[ToolAdapter]:
    return [a for a in all_adapters() if target_type in a.input_types]


register(SherlockAdapter())
