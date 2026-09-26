from __future__ import annotations

from app.adapters.amass import AmassAdapter
from app.adapters.base import ToolAdapter
from app.adapters.crtsh import CrtShAdapter
from app.adapters.h8mail import H8mailAdapter
from app.adapters.holehe import HoleheAdapter
from app.adapters.maigret import MaigretAdapter
from app.adapters.sherlock import SherlockAdapter
from app.adapters.spiderfoot import SpiderFootAdapter
from app.adapters.theharvester import TheHarvesterAdapter
from app.adapters.websearch import BraveSearchAdapter, DuckDuckGoAdapter

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


CORE_ADAPTERS: tuple[type[ToolAdapter], ...] = (
    SherlockAdapter,
    MaigretAdapter,
    HoleheAdapter,
    H8mailAdapter,
    TheHarvesterAdapter,
    CrtShAdapter,
    AmassAdapter,
    SpiderFootAdapter,
    DuckDuckGoAdapter,
    BraveSearchAdapter,
)

for _cls in CORE_ADAPTERS:
    register(_cls())
