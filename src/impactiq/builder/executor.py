"""The deterministic fix executor.

Everything here is plain, validated Web API code that a CLI can drive. The
model's only job is to produce a FixSpec; nothing in this module free-forms
requests from tokens.

Fix-only is STRUCTURAL, not policy:
* :class:`SandboxClient` has no record-POST surface at all. Record/flow
  updates go through ``patch`` which always sends ``If-Match: *`` (update
  only — the request fails rather than upserts). Metadata updates go through
  ``put_metadata`` which only accepts ``EntityDefinitions(...)`` paths (an
  existing definition, by key). The single allowed POST is the
  ``PublishXml`` action — required to surface metadata fixes, creates
  nothing.
* Every operation first locates its target via :func:`locate_table` /
  :func:`locate_flow`, which verify membership in the dedicated sandbox
  solution (the solution wall) and refuse otherwise.
* Flow definition patches capture a before-image and roll back on failure;
  a re-defined flow is only re-activated when the platform accepted the
  definition.
"""

from __future__ import annotations

import json
import re
import time
from typing import Any

import httpx
from azure.identity import ClientSecretCredential

from ..audit import audit_log
from ..dataverse_client import ensure_os_trust
from ..settings import Settings
from . import BuilderRefusal, FixReport, assert_builder_walls

API_VERSION = "v9.2"

# Component types in solutioncomponents (Microsoft documented values).
COMPONENT_TYPE_ENTITY = 1
COMPONENT_TYPE_WORKFLOW = 29

# The only properties a v1 fix may change — anything else is refused.
TABLE_FIXABLE = {"display_name", "description"}
COLUMN_FIXABLE = {"display_name", "description", "required_level"}
REQUIRED_LEVELS = {"None", "Recommended", "ApplicationRequired"}

FLOW_STATE = {"on": (1, 2), "off": (0, 1)}  # statecode, statuscode


class SandboxClient:
    """SP-authenticated Web API client for the SANDBOX environment only.

    Construction runs :func:`assert_builder_walls` — there is no way to point
    this client at the analysis environment.
    """

    def __init__(self, settings: Settings):
        base = assert_builder_walls(settings)
        ensure_os_trust()
        self.base_url = base
        self.api_base = f"{base}/api/data/{API_VERSION}"
        self._scope = f"{base}/.default"
        self._credential = ClientSecretCredential(
            tenant_id=settings.entra_tenant_id,  # type: ignore[arg-type]
            client_id=settings.impactiq_client_id,  # type: ignore[arg-type]
            client_secret=settings.impactiq_client_secret,  # type: ignore[arg-type]
        )
        self._token: str | None = None
        self._token_expiry: float = 0.0
        # Workflow activate/deactivate can take well over 30s server-side;
        # a premature client timeout strands the flow mid-transition.
        self._http = httpx.Client(timeout=120.0)

    def __enter__(self) -> "SandboxClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._http.close()

    def _bearer(self) -> str:
        if self._token is None or time.time() >= self._token_expiry - 60:
            tok = self._credential.get_token(self._scope)
            self._token = tok.token
            self._token_expiry = float(tok.expires_on)
        return self._token

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        h = {
            "Authorization": f"Bearer {self._bearer()}",
            "Accept": "application/json",
            "OData-MaxVersion": "4.0",
            "OData-Version": "4.0",
        }
        if extra:
            h.update(extra)
        return h

    @staticmethod
    def _err(resp: httpx.Response) -> str:
        detail = resp.text
        try:
            body = resp.json()
            if isinstance(body, dict) and "error" in body:
                detail = body["error"].get("message", detail)
        except Exception:
            pass
        return f"HTTP {resp.status_code}: {detail[:400]}"

    def get(self, path: str, params: dict | None = None) -> dict:
        try:
            resp = self._http.get(
                f"{self.api_base}/{path}", params=params, headers=self._headers()
            )
        except httpx.HTTPError as exc:
            raise BuilderRefusal(f"sandbox read failed — {exc!r}") from exc
        if resp.status_code >= 400:
            raise BuilderRefusal(f"sandbox read failed — {self._err(resp)}")
        return resp.json()

    def patch(self, path: str, payload: dict) -> None:
        """Update-only PATCH: ``If-Match: *`` means a missing target FAILS
        instead of upserting — the fix-only wall, enforced by the wire.
        Transport errors surface as BuilderRefusal so callers' rollback
        handling covers them like any platform rejection."""
        try:
            resp = self._http.patch(
                f"{self.api_base}/{path}",
                json=payload,
                headers=self._headers({"Content-Type": "application/json", "If-Match": "*"}),
            )
        except httpx.HTTPError as exc:
            raise BuilderRefusal(f"sandbox update failed — {exc!r}") from exc
        if resp.status_code not in (200, 204):
            raise BuilderRefusal(f"sandbox update failed — {self._err(resp)}")

    def put_metadata(self, path: str, payload: dict) -> None:
        """Full-definition metadata update (read-modify-write). Only
        EntityDefinitions paths are accepted — an existing definition by key."""
        if not path.startswith("EntityDefinitions("):
            raise BuilderRefusal(f"put_metadata only updates EntityDefinitions paths, got {path!r}")
        try:
            resp = self._http.put(
                f"{self.api_base}/{path}",
                json=payload,
                headers=self._headers(
                    {"Content-Type": "application/json", "MSCRM.MergeLabels": "true"}
                ),
            )
        except httpx.HTTPError as exc:
            raise BuilderRefusal(f"sandbox metadata update failed — {exc!r}") from exc
        if resp.status_code not in (200, 204):
            raise BuilderRefusal(f"sandbox metadata update failed — {self._err(resp)}")

    def publish(self, table_logical_name: str) -> None:
        """PublishXml for one table — surfaces metadata fixes. Creates nothing."""
        resp = self._http.post(
            f"{self.api_base}/PublishXml",
            json={"ParameterXml": f"<importexportxml><entities><entity>{table_logical_name}</entity></entities></importexportxml>"},
            headers=self._headers({"Content-Type": "application/json"}),
        )
        if resp.status_code not in (200, 204):
            raise BuilderRefusal(f"publish failed — {self._err(resp)}")


# ── solution wall ────────────────────────────────────────────────────────────


def solution_id(client: SandboxClient, unique_name: str) -> str:
    data = client.get(
        "solutions",
        {"$select": "solutionid,uniquename", "$filter": f"uniquename eq '{unique_name}'"},
    )
    rows = data.get("value", [])
    if not rows:
        raise BuilderRefusal(f"solution {unique_name!r} not found in the sandbox")
    return rows[0]["solutionid"]


def _in_solution(client: SandboxClient, sol_id: str, object_id: str, component_type: int) -> bool:
    data = client.get(
        "solutioncomponents",
        {
            "$select": "solutioncomponentid",
            "$filter": (
                f"_solutionid_value eq {sol_id} and objectid eq {object_id} "
                f"and componenttype eq {component_type}"
            ),
        },
    )
    return bool(data.get("value"))


def locate_table(client: SandboxClient, solution_unique: str, logical_name: str) -> dict:
    """The table's metadata row, IFF it belongs to the sandbox solution."""
    data = client.get(
        f"EntityDefinitions(LogicalName='{logical_name}')",
        {"$select": "MetadataId,LogicalName,DisplayName,Description"},
    )
    sol = solution_id(client, solution_unique)
    if not _in_solution(client, sol, data["MetadataId"], COMPONENT_TYPE_ENTITY):
        raise BuilderRefusal(
            f"table {logical_name!r} exists but is NOT in solution "
            f"{solution_unique!r} — outside the fix scope"
        )
    return data


_FLOW_SELECT = "workflowid,name,statecode,statuscode,category,clientdata,description"


def locate_flow(client: SandboxClient, solution_unique: str, name: str) -> dict:
    """The modern-flow workflow row by display name, IFF in the solution.

    Name resolution is TOLERANT (the model often has a partial name; sandbox
    twins carry their live component's name): exact match first, then a
    substring fallback — unique hit proceeds, multiple hits refuse with the
    candidates, zero hits refuse with the sandbox's flow list so the caller
    can self-correct in one step."""
    safe = name.replace("'", "''")
    data = client.get(
        "workflows",
        {"$select": _FLOW_SELECT, "$filter": f"name eq '{safe}' and category eq 5"},
    )
    rows = data.get("value", [])
    if not rows:
        data = client.get(
            "workflows",
            {"$select": _FLOW_SELECT, "$filter": f"contains(name, '{safe}') and category eq 5"},
        )
        rows = data.get("value", [])
        if len(rows) > 1:
            names = sorted(r["name"] for r in rows)[:8]
            raise BuilderRefusal(
                f"multiple sandbox flows match {name!r}: {names} — call again "
                "with the exact name"
            )
    if not rows:
        listing = client.get(
            "workflows", {"$select": "name", "$filter": "category eq 5"}
        )
        names = sorted(r["name"] for r in listing.get("value", []))[:10]
        raise BuilderRefusal(
            f"no cloud flow named {name!r} in the sandbox; the sandbox's "
            f"cloud flows are: {names}"
        )
    flow = rows[0]
    sol = solution_id(client, solution_unique)
    if not _in_solution(client, sol, flow["workflowid"], COMPONENT_TYPE_WORKFLOW):
        raise BuilderRefusal(
            f"flow {name!r} exists but is NOT in solution {solution_unique!r} "
            "— outside the fix scope"
        )
    return flow


def recent_flow_runs(client: SandboxClient, workflow_id: str, top: int = 5) -> list[dict]:
    """The flow's most recent runs (flowrun table) — the failure evidence a
    grounded fix proposal needs. Defensive: column availability varies by
    version, so degrade rather than fail the inspect."""
    selects = ("name,status,starttime,endtime,errorcode,errormessage", "name,status,starttime")
    for select in selects:
        try:
            data = client.get(
                "flowruns",
                {
                    "$select": select,
                    "$filter": f"_workflow_value eq {workflow_id}",
                    "$orderby": "starttime desc",
                    "$top": str(top),
                },
            )
            return [
                {k: v for k, v in row.items() if not k.startswith("@")}
                for row in data.get("value", [])
            ]
        except BuilderRefusal:
            continue
    return []


FLOW_API = "https://api.flow.microsoft.com"


def _environment_id(client: SandboxClient) -> str:
    org = client.get(
        "RetrieveCurrentOrganization(AccessType=Microsoft.Dynamics.CRM.EndpointAccessType'Default')"
    )
    env = (org.get("Detail") or {}).get("EnvironmentId")
    if not env:
        raise BuilderRefusal("could not resolve the sandbox EnvironmentId")
    return env


def _clip(obj: Any, limit: int = 900) -> str:
    s = obj if isinstance(obj, str) else json.dumps(obj, default=str)
    return s if len(s) <= limit else s[:limit] + "…(truncated)"


def child_flow_references(doc: dict) -> list[dict]:
    """'Run a Child Flow' actions in a definition — the drill-down seeds for
    repeating the fix protocol on the child."""
    definition = (doc.get("properties") or {}).get("definition") or doc.get("definition") or {}
    found: list = []
    _collect_actions(definition.get("actions") or {}, found)
    refs = []
    for name, act in found:
        if act.get("type") == "Workflow":
            host = (act.get("inputs") or {}).get("host") or {}
            refs.append(
                {"action": name, "workflow_reference": host.get("workflowReferenceName")}
            )
    return refs


def _leaf_failed_actions(props: dict) -> list[dict]:
    """The actions worth reporting from a run's expanded properties: every
    Failed action, with container failures ('ActionFailed' = a child failed)
    flagged so callers fetch response bodies only for the real leaves."""
    out = []
    for name, act in (props.get("actions") or {}).items():
        if act.get("status") != "Failed":
            continue
        out.append(
            {
                "action": name,
                "code": act.get("code"),
                "error": act.get("error"),
                "is_leaf": act.get("code") != "ActionFailed",
                "outputs_uri": (act.get("outputsLink") or {}).get("uri"),
                "inputs_uri": (act.get("inputsLink") or {}).get("uri"),
            }
        )
    return out


def _run_level_only(run: dict, reason: str) -> dict:
    """Degraded forensics: the run-LEVEL error already in Dataverse, used when
    the step-level Power Automate API read isn't available (no delegated token,
    or the middle-tier app lacks the Power Automate grant). Better than a bare
    failure - it usually still names the problem - and points at the portal."""
    return {
        "run": run.get("name"),
        "started": run.get("starttime"),
        "status": run.get("status"),
        "run_error_code": run.get("errorcode"),
        "run_error_message": run.get("errormessage"),
        "step_detail": (
            "unavailable - step-level forensics need the Power Automate API "
            f"({reason}). Showing the run-level error; open the run in the "
            "Power Automate portal for the exact failing action."
        ),
    }


def failed_run_details(
    client: Any,
    settings: Settings,
    workflow_id: str,
    top: int = 1,
    user_assertion: str | None = None,
) -> list[dict]:
    """Maker-grade run forensics — what a maker sees clicking into a failed
    run in the portal: WHICH action failed, the platform's actual error
    response body, and the inputs the action sent. The flowruns table only
    stores the top-level 'ActionFailed' summary; the detail lives behind the
    Power Automate run API, which rejects app-only auth — so this read uses
    the DELEGATED user token (consistent with the two-identity rule: run
    payloads are content, not structure).

    ``client`` is duck-typed (`.get(path, params)`): SandboxClient for the
    build twin, DataverseClient for the LIVE environment — the live
    diagnosis (`flow_run_details` engine tool) gets the same evidence depth
    as the fix path."""
    runs = client.get(
        "flowruns",
        {
            "$select": "name,status,starttime,resourceid,errorcode,errormessage",
            "$filter": f"_workflow_value eq {workflow_id} and status eq 'Failed'",
            "$orderby": "starttime desc",
            "$top": str(top),
        },
    ).get("value", [])
    if not runs:
        return []
    env = _environment_id(client)
    from ..agents.runtime import delegated_credential

    # The Power Automate run API only accepts a DELEGATED token: On-Behalf-Of
    # the signed-in user when hosted, or the local browser sign-in for the CLI.
    # If that token can't be acquired (no delegated identity, or the middle-tier
    # app has no Power Automate grant yet), degrade to the run-LEVEL error
    # already in Dataverse instead of failing the whole diagnosis.
    try:
        token = (
            delegated_credential(settings, user_assertion)
            .get_token("https://service.flow.microsoft.com//.default")
            .token
        )
    except Exception as exc:  # noqa: BLE001 — forensics degrade, never fail
        return [_run_level_only(r, f"{type(exc).__name__}: {exc}") for r in runs]
    details: list[dict] = []
    with httpx.Client(timeout=30.0) as http:
        for run in runs:
            entry: dict = {"run": run["name"], "started": run.get("starttime")}
            resp = http.get(
                f"{FLOW_API}/providers/Microsoft.ProcessSimple/environments/"
                f"{env}/flows/{run['resourceid']}/runs/{run['name']}",
                params={"$expand": "properties/actions", "api-version": "2016-11-01"},
                headers={"Authorization": f"Bearer {token}"},
            )
            if resp.status_code != 200:
                entry["error"] = f"run API HTTP {resp.status_code}"
                entry["run_error_code"] = run.get("errorcode")
                entry["run_error_message"] = run.get("errormessage")
                details.append(entry)
                continue
            props = resp.json().get("properties", {})
            entry["run_error"] = props.get("error")

            def _fetch(uri: str | None) -> Any:
                if not uri:
                    return None
                try:
                    return http.get(uri).json()
                except Exception as exc:  # noqa: BLE001 — forensics degrade
                    return f"(fetch failed: {exc})"

            # The trigger's raw outputs — the values every downstream step
            # consumes (triggerOutputs()), so a bad input can be traced to
            # its source.
            trig = props.get("trigger") or {}
            tout = _fetch((trig.get("outputsLink") or {}).get("uri"))
            if tout is not None:
                entry["trigger_outputs"] = _clip(
                    (tout or {}).get("body") if isinstance(tout, dict) else tout
                )

            failed = []
            steps = []
            actions = props.get("actions") or {}
            for aname, act in list(actions.items())[:12]:
                step = {"action": aname, "status": act.get("status"), "code": act.get("code")}
                # Raw I/O for EVERY step (clipped) — diagnosing one step often
                # needs the output of the step that fed it.
                ain = _fetch((act.get("inputsLink") or {}).get("uri"))
                if ain is not None:
                    step["inputs"] = _clip(
                        (ain or {}).get("parameters") or ain if isinstance(ain, dict) else ain
                    )
                aout = _fetch((act.get("outputsLink") or {}).get("uri"))
                if aout is not None:
                    step["outputs"] = _clip(
                        (aout or {}).get("body") if isinstance(aout, dict) else aout
                    )
                steps.append(step)
            for act in _leaf_failed_actions(props):
                item = {"action": act["action"], "code": act["code"], "error": act["error"]}
                if act["is_leaf"]:
                    # The connector's response body holds the REAL platform
                    # error; the inputs show the values actually sent. Full
                    # (unclipped) — this is the diagnosis payload.
                    body = _fetch(act["outputs_uri"])
                    if isinstance(body, dict):
                        item["response_body"] = body.get("body")
                    sent = _fetch(act["inputs_uri"])
                    if isinstance(sent, dict):
                        item["inputs_sent"] = sent.get("parameters") or sent
                failed.append(item)
            entry["steps"] = steps
            entry["failed_actions"] = failed
            details.append(entry)
    return details


# Lookup binds must be '<entityset>(<id>)' (optionally a full Web API URL).
_BIND_SHAPE = re.compile(r"^(?:https?://\S+/)?[A-Za-z_][A-Za-z0-9_]*\(.+\)$")


def table_schema(client: SandboxClient, table: str) -> dict:
    """Column semantics for one sandbox table — the grounding every row-write
    fix needs: which columns are AUTONUMBER (platform-generated, never set),
    which are lookups and the exact ``<entityset>(<id>)`` bind shape, what is
    required. Accepts a logical name or an entity set name (the connector's
    ``entityName`` is the set name). Read-only — no solution wall."""
    try:
        ent = client.get(
            f"EntityDefinitions(LogicalName='{table}')",
            {"$select": "LogicalName,EntitySetName"},
        )
    except BuilderRefusal:
        rows = client.get(
            "EntityDefinitions",
            {
                "$select": "LogicalName,EntitySetName",
                "$filter": f"EntitySetName eq '{table}'",
            },
        ).get("value", [])
        if not rows:
            raise BuilderRefusal(
                f"no sandbox table with logical or entity-set name {table!r}"
            ) from None
        ent = rows[0]
    logical = ent["LogicalName"]
    attrs = client.get(
        f"EntityDefinitions(LogicalName='{logical}')/Attributes",
        {
            "$select": "LogicalName,AttributeType,AutoNumberFormat,"
            "RequiredLevel,DisplayName,AttributeOf"
        },
    ).get("value", [])
    columns: list[dict] = []
    for a in attrs:
        if a.get("AttributeOf"):
            continue  # shadow columns (…name / yominame) — never set directly
        atype = a.get("AttributeType")
        if atype in ("Virtual", "EntityName"):
            continue
        col: dict = {
            "column": a["LogicalName"],
            "type": atype,
            "display": ((a.get("DisplayName") or {}).get("UserLocalizedLabel") or {}).get(
                "Label"
            ),
            "required": (a.get("RequiredLevel") or {}).get("Value"),
        }
        if a.get("AutoNumberFormat"):
            col["autonumber"] = a["AutoNumberFormat"]
            if col["required"] == "ApplicationRequired":
                # The connector validates required properties at save time, so
                # removal alone is rejected until the requirement is lifted.
                col["note"] = (
                    "autonumber AND business-required: the connector demands a "
                    "value until the requirement is lifted — fix with "
                    "alter_column required_level='None' FIRST, then remove the "
                    "parameter so the platform generates the number"
                )
            else:
                col["note"] = "platform-generated — do NOT set; remove the parameter instead"
        if atype in ("Lookup", "Customer", "Owner"):
            try:
                targets = client.get(
                    f"EntityDefinitions(LogicalName='{logical}')/Attributes"
                    f"(LogicalName='{a['LogicalName']}')"
                    "/Microsoft.Dynamics.CRM.LookupAttributeMetadata",
                    {"$select": "Targets"},
                ).get("Targets") or []
                binds = []
                for t in targets:
                    tset = client.get(
                        f"EntityDefinitions(LogicalName='{t}')",
                        {"$select": "EntitySetName"},
                    ).get("EntitySetName")
                    if tset:
                        binds.append(f"{tset}(<{t} id>)")
                col["lookup_targets"] = targets
                if binds:
                    col["bind_format"] = binds
            except Exception:  # noqa: BLE001 — grounding degrades, never fails
                col["lookup_targets"] = "(unresolved)"
        columns.append(col)
    return {
        "table": logical,
        "entity_set": ent.get("EntitySetName"),
        "note": (
            "set lookups via item/<Column>@odata.bind = '<entityset>(<id>)'; "
            "autonumber columns are platform-generated — remove rather than set"
        ),
        "columns": columns,
    }


# ── fix operations ───────────────────────────────────────────────────────────


def _label(text: str) -> dict:
    return {
        "@odata.type": "Microsoft.Dynamics.CRM.Label",
        "LocalizedLabels": [
            {
                "@odata.type": "Microsoft.Dynamics.CRM.LocalizedLabel",
                "Label": text,
                "LanguageCode": 1033,
            }
        ],
    }


def set_flow_state(
    client: SandboxClient, solution_unique: str, flow_name: str, state: str
) -> dict:
    if state not in FLOW_STATE:
        raise BuilderRefusal(f"flow state must be on|off, got {state!r}")
    flow = locate_flow(client, solution_unique, flow_name)
    statecode, statuscode = FLOW_STATE[state]
    before = {"statecode": flow["statecode"], "statuscode": flow["statuscode"]}
    client.patch(
        f"workflows({flow['workflowid']})",
        {"statecode": statecode, "statuscode": statuscode},
    )
    audit_log(
        "builder_fix",
        {
            "op": "set_flow_state",
            "flow": flow_name,
            "workflowid": flow["workflowid"],
            "before": before,
            "after": {"statecode": statecode, "statuscode": statuscode},
        },
    )
    return {"component": f"flow:{flow_name}", "change": f"state -> {state}"}


def _write_clientdata(
    client: SandboxClient,
    flow: dict,
    new_doc: dict,
    *,
    report: FixReport,
    change: str,
    op_name: str,
) -> None:
    """Shared clientdata writer: deactivate → patch → reactivate, with
    before-image rollback and the honest done/partial/outstanding contract."""
    flow_name = flow["name"]
    before_clientdata = flow.get("clientdata")
    was_on = flow["statecode"] == 1
    wid = flow["workflowid"]
    if was_on:
        client.patch(f"workflows({wid})", {"statecode": 0, "statuscode": 1})
    try:
        client.patch(f"workflows({wid})", {"clientdata": json.dumps(new_doc)})
    except BuilderRefusal as exc:
        # Roll back to the before-image; leave state off for human review.
        client.patch(f"workflows({wid})", {"clientdata": before_clientdata})
        report.outstanding.append(
            {
                "step": f"repair flow {flow_name!r} in the designer",
                "reason": f"platform rejected the new definition ({exc}); rolled back",
            }
        )
        audit_log(
            "builder_fix",
            {"op": op_name, "flow": flow_name, "result": "rolled_back", "error": str(exc)},
        )
        return
    if was_on:
        try:
            client.patch(f"workflows({wid})", {"statecode": 1, "statuscode": 2})
            report.done.append(
                {"component": f"flow:{flow_name}", "change": f"{change} + reactivated"}
            )
        except BuilderRefusal as exc:
            report.partial.append(
                {
                    "component": f"flow:{flow_name}",
                    "change": f"{change} but left OFF",
                    "reason": f"activation failed: {exc}",
                }
            )
    else:
        report.done.append(
            {"component": f"flow:{flow_name}", "change": f"{change} (flow was off; left OFF)"}
        )
    audit_log(
        "builder_fix",
        {"op": op_name, "flow": flow_name, "workflowid": wid,
         "before_chars": len(before_clientdata or ""), "change": change,
         "result": "applied"},
    )


def patch_flow_definition(
    client: SandboxClient,
    solution_unique: str,
    flow_name: str,
    new_clientdata: str,
    *,
    report: FixReport,
) -> None:
    """Repair a flow's FULL definition with before-image rollback.

    The new clientdata must be valid JSON that PRESERVES the existing
    connectionReferences keys (fix-only: a repair must not silently rewire
    connections — a genuinely new connector is an `outstanding` human step).
    For single-value changes prefer :func:`set_flow_action_parameter` —
    regenerating a whole definition as an escaped string is error-prone.
    """
    flow = locate_flow(client, solution_unique, flow_name)
    try:
        new_doc = json.loads(new_clientdata)
    except json.JSONDecodeError as exc:
        raise BuilderRefusal(f"new clientdata is not valid JSON: {exc}") from exc
    old_refs = set((json.loads(flow.get("clientdata") or "{}").get("connectionReferences") or {}))
    new_refs = set((new_doc.get("connectionReferences") or {}))
    if old_refs and not old_refs <= new_refs:
        raise BuilderRefusal(
            "repaired definition drops existing connectionReferences "
            f"{sorted(old_refs - new_refs)} — fixes must preserve connections"
        )
    _write_clientdata(
        client, flow, new_doc,
        report=report, change="definition repaired", op_name="patch_flow_definition",
    )


def _collect_actions(actions: dict, found: list) -> None:
    for key, act in (actions or {}).items():
        if not isinstance(act, dict):
            continue
        found.append((key, act))
        _collect_actions(act.get("actions") or {}, found)
        _collect_actions((act.get("else") or {}).get("actions") or {}, found)


def _guard_row_write(
    client: SandboxClient, action_params: dict, parameter: str, value: Any
) -> None:
    """Metadata grounding, enforced at the wire: a row-write parameter is
    checked against the TARGET TABLE's schema so the executor refuses what
    the platform would reject at runtime — a literal in an autonumber column,
    a lookup bind that isn't '<entityset>(<id>)'. Degrades silently when the
    schema can't be read (the guard must never block a legitimate fix)."""
    if not parameter.startswith("item/"):
        return
    entity_set = action_params.get("entityName")
    if not isinstance(entity_set, str) or not entity_set:
        return
    column = parameter[len("item/"):].split("@", 1)[0].lower()
    try:
        schema = table_schema(client, entity_set)
    except Exception:  # noqa: BLE001
        return
    info = next((c for c in schema["columns"] if c["column"] == column), None)
    if info is None:
        return
    if info.get("autonumber"):
        extra = (
            " (it is also business-required, so FIRST alter_column "
            "required_level='None', THEN remove)"
            if info.get("required") == "ApplicationRequired"
            else ""
        )
        raise BuilderRefusal(
            f"column {column!r} ({info.get('display')}) is an AUTONUMBER "
            f"[{info['autonumber']}] — the platform generates its value; "
            f"REMOVE the parameter (value=null) instead of setting a literal{extra}"
        )
    if parameter.endswith("@odata.bind") and not _BIND_SHAPE.match(str(value)):
        hint = "; ".join(info.get("bind_format") or []) or "<entityset>(<id>)"
        raise BuilderRefusal(
            f"{parameter!r} is a lookup bind — its value must be "
            f"'<entityset>(<id>)' (the id may be an @-expression), "
            f"e.g. {hint}; got {value!r}"
        )


def set_flow_action_parameter(
    client: SandboxClient,
    solution_unique: str,
    flow_name: str,
    action: str,
    parameter: str,
    value: Any,
    *,
    report: FixReport,
) -> None:
    """SURGICAL flow repair: set (or, with ``value=None``, REMOVE) one
    parameter of one existing action.

    Deterministic JSON edit — the model names the action and parameter, this
    code does the document surgery, so there is no whole-definition string
    for the model to mangle. connectionReferences are untouched by
    construction. Action lookup is tolerant (exact → case-insensitive →
    unique substring) and a miss lists the flow's actions. Row writes are
    schema-guarded (:func:`_guard_row_write`)."""
    flow = locate_flow(client, solution_unique, flow_name)
    doc = json.loads(flow.get("clientdata") or "{}")
    definition = (doc.get("properties") or {}).get("definition") or doc.get("definition") or {}
    found: list = []
    _collect_actions(definition.get("actions") or {}, found)
    if not found:
        raise BuilderRefusal(f"flow {flow_name!r} has no actions in its definition")
    by_exact = [a for a in found if a[0] == action]
    by_ci = [a for a in found if a[0].lower() == action.lower()]
    by_sub = [a for a in found if action.lower() in a[0].lower()]
    target = (by_exact or by_ci or (by_sub if len(by_sub) == 1 else []))
    if not target:
        names = sorted(k for k, _ in found)
        raise BuilderRefusal(
            f"no action matching {action!r} in flow {flow_name!r}; its actions "
            f"are: {names}"
        )
    name, act = target[0]
    params = act.setdefault("inputs", {}).setdefault("parameters", {})
    if value is None:
        if parameter not in params:
            raise BuilderRefusal(
                f"parameter {parameter!r} is not set on action {name!r} — "
                f"nothing to remove; its parameters are {sorted(params)}"
            )
        before_value = params.pop(parameter)
        change = f"action {name!r}: removed {parameter} (was {before_value!r})"
    else:
        _guard_row_write(client, params, parameter, value)
        before_value = params.get(parameter, "(absent)")
        params[parameter] = value
        change = f"action {name!r}: {parameter} = {value!r} (was {before_value!r})"
    _write_clientdata(
        client, flow, doc,
        report=report,
        change=change,
        op_name="set_flow_action_parameter",
    )


def alter_table(
    client: SandboxClient, solution_unique: str, logical_name: str, changes: dict
) -> dict:
    unknown = set(changes) - TABLE_FIXABLE
    if unknown:
        raise BuilderRefusal(f"table fix only supports {sorted(TABLE_FIXABLE)}; got {sorted(unknown)}")
    locate_table(client, solution_unique, logical_name)  # solution wall
    full = client.get(f"EntityDefinitions(LogicalName='{logical_name}')")
    before = {"DisplayName": full.get("DisplayName"), "Description": full.get("Description")}
    if "display_name" in changes:
        full["DisplayName"] = _label(str(changes["display_name"]))
    if "description" in changes:
        full["Description"] = _label(str(changes["description"]))
    # Read-modify-write of the full definition (documented metadata update).
    full.pop("@odata.context", None)
    client.put_metadata(f"EntityDefinitions(LogicalName='{logical_name}')", full)
    client.publish(logical_name)
    audit_log(
        "builder_fix",
        {"op": "alter_table", "table": logical_name, "before": before, "changes": changes},
    )
    return {"component": f"table:{logical_name}", "change": ", ".join(sorted(changes))}


def alter_column(
    client: SandboxClient,
    solution_unique: str,
    table_logical: str,
    column_logical: str,
    changes: dict,
) -> dict:
    unknown = set(changes) - COLUMN_FIXABLE
    if unknown:
        raise BuilderRefusal(
            f"column fix only supports {sorted(COLUMN_FIXABLE)}; got {sorted(unknown)}"
        )
    if "required_level" in changes and changes["required_level"] not in REQUIRED_LEVELS:
        raise BuilderRefusal(
            f"required_level must be one of {sorted(REQUIRED_LEVELS)}"
        )
    locate_table(client, solution_unique, table_logical)  # solution wall
    path = (
        f"EntityDefinitions(LogicalName='{table_logical}')"
        f"/Attributes(LogicalName='{column_logical}')"
    )
    full = client.get(path)
    if "@odata.type" not in full:
        raise BuilderRefusal(
            f"column {column_logical!r}: attribute type not identifiable — "
            "fix it in the maker portal instead"
        )
    before = {
        "DisplayName": full.get("DisplayName"),
        "Description": full.get("Description"),
        "RequiredLevel": full.get("RequiredLevel"),
    }
    if "display_name" in changes:
        full["DisplayName"] = _label(str(changes["display_name"]))
    if "description" in changes:
        full["Description"] = _label(str(changes["description"]))
    if "required_level" in changes:
        full["RequiredLevel"] = {
            "Value": changes["required_level"],
            "CanBeChanged": True,
            "ManagedPropertyLogicalName": "canmodifyrequirementlevelsettings",
        }
    full.pop("@odata.context", None)
    client.put_metadata(path, full)
    client.publish(table_logical)
    audit_log(
        "builder_fix",
        {"op": "alter_column", "table": table_logical, "column": column_logical,
         "before": before, "changes": changes},
    )
    return {
        "component": f"column:{table_logical}.{column_logical}",
        "change": ", ".join(sorted(changes)),
    }


# ── FixSpec runner ───────────────────────────────────────────────────────────


def run_fixspec(settings: Settings, spec: dict) -> FixReport:
    """Execute a validated FixSpec: {"ops": [...]} — each op fully typed.

    Op shapes:
      {"op": "set_flow_state", "flow": "<name>", "state": "on"|"off"}
      {"op": "set_flow_action_parameter", "flow": "<name>", "action": "<action name>",
       "parameter": "<e.g. item/new_name>", "value": <any JSON>}
      {"op": "patch_flow_definition", "flow": "<name>", "clientdata": "<json str>"}
      {"op": "alter_table", "table": "<logical>", "set": {...}}
      {"op": "alter_column", "table": "<logical>", "column": "<logical>", "set": {...}}
    Unknown ops are refused (never silently skipped).
    """
    solution = (settings.impactiq_build_solution or "").strip()
    report = FixReport()
    ops = spec.get("ops") or []
    if not isinstance(ops, list) or not ops:
        raise BuilderRefusal("FixSpec must contain a non-empty ops list")
    with SandboxClient(settings) as client:
        for op in ops:
            kind = (op or {}).get("op")
            try:
                if kind == "set_flow_state":
                    report.done.append(
                        set_flow_state(client, solution, op["flow"], op["state"])
                    )
                elif kind == "set_flow_action_parameter":
                    set_flow_action_parameter(
                        client, solution, op["flow"], op["action"],
                        op["parameter"], op.get("value"), report=report,
                    )
                elif kind == "patch_flow_definition":
                    patch_flow_definition(
                        client, solution, op["flow"], op["clientdata"], report=report
                    )
                elif kind == "alter_table":
                    report.done.append(
                        alter_table(client, solution, op["table"], op.get("set") or {})
                    )
                elif kind == "alter_column":
                    report.done.append(
                        alter_column(
                            client, solution, op["table"], op["column"], op.get("set") or {}
                        )
                    )
                else:
                    raise BuilderRefusal(f"unknown fix op {kind!r}")
            except BuilderRefusal as exc:
                report.outstanding.append({"step": f"op {kind}: not applied (needs correction)", "reason": str(exc)})
            except KeyError as exc:
                report.outstanding.append(
                    {"step": f"op {kind}: malformed", "reason": f"missing field {exc}"}
                )
    return report
