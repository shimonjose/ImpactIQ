"""Pytest fixtures: a sample estate fragment and a built graph."""

from __future__ import annotations

import pytest

from impactiq.connectors.base import EstateFragment
from impactiq.graph import ImpactGraph, build_graph

from tests.fixtures.estate import NOW, make_demo_fragment


@pytest.fixture
def now_str() -> str:
    return NOW


@pytest.fixture
def fragment() -> EstateFragment:
    return make_demo_fragment()


@pytest.fixture
def graph(fragment: EstateFragment) -> ImpactGraph:
    return build_graph(fragment)
