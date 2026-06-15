"""Estate-side change-collision scan.

After the dependency walk produces a blast radius, the engine looks at
``modifiedon`` / ``_modifiedby_value`` on every impacted component and flags
anything changed in the last *N* days. This is the *deterministic* half of
change-collision detection - the human-side half (Work IQ active-work signals)
runs in the Context agent.

Pure function over the in-memory subgraph. The ``FlowsConnector`` already
captured ``modified_on`` / ``modified_by`` on Flow nodes, so the most common
case (recently-edited flow in the radius) needs no extra Dataverse call.

Anchor-kind-agnostic: works on whatever subgraph the walk produced - column,
flow, view, role.
"""

from __future__ import annotations

from datetime import datetime, timezone

from ..connectors.base import Node
from .model import RecentChange, SubGraph


# Metadata keys the connectors use when populating modified_on / modified_by.
_MODIFIED_ON_KEYS = ("modified_on", "modifiedon")
_MODIFIED_BY_KEYS = ("modified_by", "_modifiedby_value", "modifiedby_id")


def _meta(node: Node, keys: tuple[str, ...]) -> str | None:
    for k in keys:
        v = node.metadata.get(k)
        if v:
            return str(v)
    return None


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    # Accept Z suffix or explicit offset.
    s = ts.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def recent_change_scan(
    subgraph: SubGraph,
    *,
    now: datetime | str | None = None,
    threshold_days: int = 14,
) -> list[RecentChange]:
    """Return components in the subgraph modified within ``threshold_days``.

    ``now`` is overridable for tests. Components missing modified_on
    metadata are skipped (not flagged): "we don't know" is not "recently changed."
    """
    if isinstance(now, str):
        now_dt = _parse(now)
    elif now is None:
        now_dt = datetime.now(timezone.utc)
    else:
        now_dt = now
    if now_dt is None:
        raise ValueError("could not parse `now`")

    hits: list[RecentChange] = []
    for node in subgraph.nodes:
        if node.id == subgraph.anchor.id:
            continue
        ts = _meta(node, _MODIFIED_ON_KEYS)
        dt = _parse(ts)
        if dt is None:
            continue
        days = (now_dt - dt).days
        if days < 0:
            # Future-dated; treat as "today" (don't drop).
            days = 0
        if days <= threshold_days:
            hits.append(
                RecentChange(
                    component=node,
                    modified_on=ts,
                    modified_by_id=_meta(node, _MODIFIED_BY_KEYS),
                    days_ago=days,
                )
            )

    # Most-recent first.
    hits.sort(key=lambda c: c.days_ago if c.days_ago is not None else 1_000_000)
    return hits
