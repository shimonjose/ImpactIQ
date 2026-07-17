"""ImpactIQ Builder - sandbox FIX carve-out.

This module ships the WALLS; the deterministic executor builds on top of them.
Every entry point must call :func:`assert_builder_walls` first - the walls
are the carve-out's safety contract:

* environment wall - writes only against ``BUILD_DATAVERSE_URL``, which must
  be set and must differ from the analysis env's ``DATAVERSE_URL``;
* fix-only wall - only components that already exist get modified (enforced
  by the executor: locate-then-PATCH, never POST);
* solution wall - components must belong to ``IMPACTIQ_BUILD_SOLUTION``;
* permission wall - the bridge verifies the requesting user holds the
  ``IMPACTIQ_BUILDER_ROLE`` security role in the sandbox before invoking;
* no deletes; deterministic FixSpec execution; audit with before-images.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class BuilderRefusal(RuntimeError):
    """A builder wall refused the operation (safety, not failure)."""


def _norm_url(url: str | None) -> str:
    return (url or "").strip().rstrip("/").lower()


def assert_builder_walls(settings: Any) -> str:
    """Validate the environment + solution walls; return the sandbox URL.

    Raises :class:`BuilderRefusal` (never proceeds degraded) when:
    * ``BUILD_DATAVERSE_URL`` is unset - there is no sandbox;
    * it equals the analysis ``DATAVERSE_URL`` (normalized) - the carve-out
      exists precisely so the analysis env is never written;
    * ``IMPACTIQ_BUILD_SOLUTION`` is unset - no solution wall to scope to.
    """
    build_url = _norm_url(getattr(settings, "build_dataverse_url", None))
    analysis_url = _norm_url(getattr(settings, "dataverse_url", None))
    if not build_url:
        raise BuilderRefusal(
            "BUILD_DATAVERSE_URL is not set - the Builder only operates "
            "against a dedicated sandbox environment."
        )
    if build_url == analysis_url:
        raise BuilderRefusal(
            "BUILD_DATAVERSE_URL equals the analysis DATAVERSE_URL - the "
            "Builder refuses to write to the analysis environment."
        )
    if not (getattr(settings, "impactiq_build_solution", None) or "").strip():
        raise BuilderRefusal(
            "IMPACTIQ_BUILD_SOLUTION is not set - fixes must be scoped to "
            "the dedicated sandbox solution."
        )
    return build_url


@dataclass
class FixReport:
    """The honest outcome contract: applied, partially applied, outstanding."""

    done: list[dict] = field(default_factory=list)
    partial: list[dict] = field(default_factory=list)
    outstanding: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "done": self.done,
            "partial": self.partial,
            "outstanding": self.outstanding,
        }
