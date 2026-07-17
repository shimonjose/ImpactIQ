"""Pytest fixtures: a sample estate fragment and a built graph."""

from __future__ import annotations

import os

# The bridge caps concurrent background jobs (429 beyond the limit - a
# production DoS bound). Stubbed job tests can briefly leave worker threads
# in "running" state, so the whole SUITE would flake against the small
# production cap; raise it for tests only. Must be set before impactiq.server
# is imported (the cap is read at import time).
os.environ.setdefault("IMPACTIQ_MAX_RUNNING_JOBS", "64")
os.environ.setdefault("IMPACTIQ_MAX_RUNNING_JOBS_PER_USER", "64")

# Hermetic test config: obviously-fake Foundry/identity values so the
# "is a model/project configured?" gates pass in CI (no .env there) and the
# suite never depends on - or touches - a real tenant. Every model/tool call
# is stubbed in the tests; these values only ever reach OFFLINE constructors.
# Set before impactiq.settings loads (python-dotenv does not override
# existing environment variables, so these also win over a local .env -
# making local runs hermetic too).
os.environ.setdefault("FOUNDRY_MODEL_DEPLOYMENT", "gpt-test")
os.environ.setdefault(
    "FOUNDRY_PROJECT_ENDPOINT",
    "https://example.services.ai.azure.com/api/projects/test-project",
)
os.environ.setdefault("ENTRA_TENANT_ID", "00000000-0000-0000-0000-000000000001")
os.environ.setdefault("IMPACTIQ_CLIENT_ID", "00000000-0000-0000-0000-000000000002")
os.environ.setdefault("IMPACTIQ_CLIENT_SECRET", "test-secret-not-real")

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
