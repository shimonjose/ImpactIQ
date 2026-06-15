"""A small but representative EstateFragment used across the engine tests.

The shape mirrors the kind of estate the engine reasons over: a few
tables, mandatory and ordinary columns, a couple of cloud flows that read
and write across them, a saved query view, two security roles, a
field-security profile, and a team. Modified-on stamps are set relative to
``NOW`` so the collision-scan test can flag the right ones.

Every engine acceptance case (Column / Flow / View / SecurityRole anchors,
defect-vs-expected, permissions diagnosis, recently-edited collision) reads
from this single fixture.
"""

from __future__ import annotations

from impactiq.connectors.base import Edge, EstateFragment, Node

# Fixed clock so collision-scan tests are deterministic.
NOW = "2026-06-02T10:00:00Z"


def make_demo_fragment() -> EstateFragment:
    f = EstateFragment()

    # ----- tables ---------------------------------------------------------
    f.add_node(Node(id="table:request", kind="Table", name="Request", raw_ref="request"))
    f.add_node(Node(id="table:contact", kind="Table", name="Contact", raw_ref="contact"))

    # ----- columns --------------------------------------------------------
    def col(table: str, name: str, *, required: str = "None") -> None:
        node_id = f"column:{table}.{name}"
        f.add_node(
            Node(
                id=node_id,
                kind="Column",
                name=name,
                raw_ref=name,
                metadata={"table": table, "required_level": required},
            )
        )
        f.add_edge(Edge(from_=f"table:{table}", relation="has_column", to=node_id))
        if required == "ApplicationRequired":
            f.add_edge(Edge(from_=node_id, relation="mandatory_on", to=f"table:{table}"))

    col("request", "status", required="ApplicationRequired")
    col("request", "resolution")
    col("request", "ownerid")
    col("contact", "fullname")

    # ----- flows ----------------------------------------------------------
    # `close_request` is the headline writer of request.status - it'll appear
    # in every Column-anchor DIAGNOSE and the collision scan picks it up.
    f.add_node(
        Node(
            id="flow:close_request",
            kind="Flow",
            name="close_request",
            raw_ref="close_request",
            metadata={
                "modified_on": "2026-05-25T12:00:00Z",  # 8 days before NOW
                "modified_by": "user-alice",
                "statecode": 1,
            },
        )
    )
    f.add_edge(Edge(from_="flow:close_request", relation="triggered_by", to="table:request"))
    f.add_edge(Edge(from_="flow:close_request", relation="writes_to", to="table:request"))
    f.add_edge(Edge(from_="flow:close_request", relation="writes_to", to="column:request.status"))
    f.add_edge(Edge(from_="flow:close_request", relation="writes_to", to="column:request.resolution"))

    # `assign_owner` writes ownerid - relevant to validate blast on request.
    f.add_node(
        Node(
            id="flow:assign_owner",
            kind="Flow",
            name="assign_owner",
            raw_ref="assign_owner",
            metadata={
                "modified_on": "2026-01-15T09:00:00Z",  # > 4 months ago
                "modified_by": "user-bob",
                "statecode": 1,
            },
        )
    )
    f.add_edge(Edge(from_="flow:assign_owner", relation="triggered_by", to="table:request"))
    f.add_edge(Edge(from_="flow:assign_owner", relation="writes_to", to="table:request"))
    f.add_edge(Edge(from_="flow:assign_owner", relation="writes_to", to="column:request.ownerid"))

    # `notify_contact` is unrelated to request; verifies the walk doesn't
    # bleed across unrelated tables.
    f.add_node(
        Node(
            id="flow:notify_contact",
            kind="Flow",
            name="notify_contact",
            raw_ref="notify_contact",
            metadata={
                "modified_on": "2026-06-01T09:00:00Z",  # 1 day ago - recent
                "modified_by": "user-carol",
                "statecode": 1,
            },
        )
    )
    f.add_edge(Edge(from_="flow:notify_contact", relation="reads_from", to="table:contact"))

    # ----- view -----------------------------------------------------------
    f.add_node(
        Node(
            id="view:open_requests",
            kind="View",
            name="Open Requests",
            raw_ref="open_requests",
        )
    )
    f.add_edge(Edge(from_="view:open_requests", relation="surfaces", to="table:request"))
    f.add_edge(Edge(from_="view:open_requests", relation="references", to="column:request.status"))
    f.add_edge(Edge(from_="view:open_requests", relation="references", to="column:request.ownerid"))

    # ----- security roles -------------------------------------------------
    f.add_node(
        Node(
            id="role:agent_role",
            kind="SecurityRole",
            name="Agent",
            raw_ref="agent_role",
        )
    )
    f.add_node(
        Node(
            id="role:viewer_role",
            kind="SecurityRole",
            name="Viewer",
            raw_ref="viewer_role",
        )
    )
    # Both roles secure the request table; one is read-only, one full.
    f.add_edge(
        Edge(
            from_="table:request",
            relation="secured_by",
            to="role:agent_role",
            metadata={"privileges": ["prvReadRequest", "prvWriteRequest"]},
        )
    )
    f.add_edge(
        Edge(
            from_="table:request",
            relation="secured_by",
            to="role:viewer_role",
            metadata={"privileges": ["prvReadRequest"]},
        )
    )

    # ----- field security -------------------------------------------------
    f.add_node(
        Node(
            id="fsp:status_fsp",
            kind="FieldSecurityProfile",
            name="Request Status FSP",
            raw_ref="status_fsp",
        )
    )
    f.add_edge(Edge(from_="column:request.status", relation="secured_by", to="fsp:status_fsp"))

    # ----- team -----------------------------------------------------------
    f.add_node(Node(id="team:team_a", kind="Team", name="Team A", raw_ref="team_a"))
    f.add_edge(Edge(from_="team:team_a", relation="member_of", to="fsp:status_fsp"))

    return f
