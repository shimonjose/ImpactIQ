"""Impact-graph engine (deterministic, no LLM).

Public API:

* ``build_graph`` - EstateFragment -> ImpactGraph
* ``resolve_anchor`` - find candidate anchor nodes for a query
* ``walk`` - the dependency walk (the engine's primary first move)
* ``score`` - explainable risk scoring
* ``recent_change_scan`` - estate-side change-collision scan
* ``diagnose_permission`` - permissions diagnosis
* ``reconcile_defect_vs_expected`` - defect-vs-expected conflict rule
"""

from .adjudication import (
    KnowledgeVerdict,
    ReconciledFinding,
    TechnicalVerdict,
    reconcile_defect_vs_expected,
)
from .build import build_graph
from .collisions import recent_change_scan
from .model import (
    Action,
    Direction,
    ImpactGraph,
    Intent,
    PermissionsDiagnosis,
    RecentChange,
    Risk,
    RiskLevel,
    SubGraph,
    WalkedEdge,
)
from .permissions import diagnose_permission
from .resolve import resolve_anchor
from .risk import score
from .traverse import walk

__all__ = [
    "build_graph",
    "resolve_anchor",
    "walk",
    "score",
    "recent_change_scan",
    "diagnose_permission",
    "reconcile_defect_vs_expected",
    "ImpactGraph",
    "SubGraph",
    "WalkedEdge",
    "Risk",
    "RiskLevel",
    "RecentChange",
    "PermissionsDiagnosis",
    "Intent",
    "Direction",
    "Action",
    "TechnicalVerdict",
    "KnowledgeVerdict",
    "ReconciledFinding",
]
