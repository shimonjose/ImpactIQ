"""Estate connector layer (read-only).

``dataverse.py`` (metadata + security reader) · ``flows.py`` (clientdata parser
+ FlowRun) · ``solutions.py`` (components + the three dependency
primitives) · ``base.py`` (`EstateScope`, `EstateFragment`, canonical ids).

The ``build_estate`` orchestrator merges all three connectors' output into one
``EstateFragment`` per scope and caches it - never re-crawl inside a turn.
"""

from __future__ import annotations

from ..dataverse_client import DataverseClient
from .base import (
    EstateFragment,
    EstateScope,
    cached_fragment,
    clear_cache,
    store_fragment,
)
from .dataverse import DataverseConnector
from .flows import FlowsConnector, parse_clientdata
from .solutions import SolutionsConnector, decode_component_type

__all__ = [
    "DataverseConnector",
    "FlowsConnector",
    "SolutionsConnector",
    "EstateScope",
    "EstateFragment",
    "parse_clientdata",
    "decode_component_type",
    "build_estate",
    "clear_cache",
]


def build_estate(
    client: DataverseClient,
    scope: EstateScope,
    *,
    use_cache: bool = True,
) -> tuple[EstateScope, EstateFragment]:
    """Read the full estate fragment for a scope.

    Returns the (resolved) scope and the merged fragment. Caches by
    ``scope.cache_key`` so a second call within the same process / turn hits
    memory rather than the platform.
    """
    sols = SolutionsConnector(client)
    scope = sols.resolve_scope(scope)

    if use_cache:
        cached = cached_fragment(scope)
        if cached is not None:
            return scope, cached

    fragment = EstateFragment()

    # 1. Solution + SolutionComponent spine + per-component dependency walk.
    fragment.merge(sols.read(scope))

    # 2. Identify the in-scope kinds the kind-specific connectors care about.
    #    `list_components` is a cheap entity read; calling it again is fine.
    components = sols.list_components(scope.solution_id)  # type: ignore[arg-type]
    table_metadata_ids = {
        str(c["objectid"]) for c in components if int(c["componenttype"]) == 1
    }
    workflow_ids = {
        str(c["objectid"]) for c in components if int(c["componenttype"]) == 29
    }

    # 3. Tables + columns + security (kind-specific canonical nodes).
    dv = DataverseConnector(client)
    dv_fragment, scoped_tables = dv.read(scope, table_metadata_ids)
    fragment.merge(dv_fragment)

    # 4. Flows: parsed clientdata edges, normalized via the table set map.
    collection_map = dv.collection_to_logical_map(scoped_tables)
    fl = FlowsConnector(client)
    fragment.merge(fl.read(workflow_ids, collection_map))

    store_fragment(scope, fragment)
    return scope, fragment
