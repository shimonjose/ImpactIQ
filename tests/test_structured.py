"""The strict-schema transform + flag gate (offline, no model calls).

The live capability is covered by a separate smoke script. These pin the
deterministic pieces: the flag defaults OFF (so the orchestrator path is
byte-identical to before) and `strictify` produces an OpenAI strict-mode-
compliant schema for OrchestratorPlan.
"""

from __future__ import annotations

from impactiq.agents.contracts import OrchestratorPlan
from impactiq.agents.structured import strictify, structured_output_enabled

# keywords the strict subset forbids (must not survive strictify)
_FORBIDDEN = {
    "minimum", "maximum", "multipleOf", "exclusiveMinimum", "exclusiveMaximum",
    "minLength", "maxLength", "pattern", "format",
    "minItems", "maxItems", "uniqueItems", "default",
}


def test_flag_off_by_default(monkeypatch):
    monkeypatch.delenv("IMPACTIQ_STRUCTURED_OUTPUT", raising=False)
    assert structured_output_enabled() is False


def test_flag_on_values(monkeypatch):
    for v in ("1", "on", "true", "YES", "enforce"):
        monkeypatch.setenv("IMPACTIQ_STRUCTURED_OUTPUT", v)
        assert structured_output_enabled() is True
    for v in ("0", "off", "", "no"):
        monkeypatch.setenv("IMPACTIQ_STRUCTURED_OUTPUT", v)
        assert structured_output_enabled() is False


def _walk_objects(node, hits):
    if isinstance(node, dict):
        if node.get("type") == "object" and "properties" in node:
            hits.append(node)
        for v in node.values():
            _walk_objects(v, hits)
    elif isinstance(node, list):
        for v in node:
            _walk_objects(v, hits)


def _all_keys(node, keys):
    if isinstance(node, dict):
        for k, v in node.items():
            keys.add(k)
            _all_keys(v, keys)
    elif isinstance(node, list):
        for v in node:
            _all_keys(v, keys)


def test_strictify_orchestrator_plan_is_strict_compliant():
    schema = strictify(OrchestratorPlan.model_json_schema())

    # every object: additionalProperties False, and all properties required
    objs: list = []
    _walk_objects(schema, objs)
    assert objs, "expected at least the root + NodeRef objects"
    for obj in objs:
        assert obj.get("additionalProperties") is False
        assert set(obj["required"]) == set(obj["properties"].keys())

    # no forbidden keyword anywhere
    keys: set = set()
    _all_keys(schema, keys)
    assert not (keys & _FORBIDDEN), f"forbidden keywords survived: {keys & _FORBIDDEN}"


def test_strictify_strips_numeric_bounds_and_marks_required():
    raw = {
        "type": "object",
        "properties": {
            "score": {"type": "integer", "minimum": 0, "maximum": 100},
            "label": {"type": "string", "maxLength": 10, "default": "x"},
        },
        # note: nothing in "required" originally
    }
    out = strictify(raw)
    assert out["additionalProperties"] is False
    assert set(out["required"]) == {"score", "label"}
    assert "minimum" not in out["properties"]["score"]
    assert "maximum" not in out["properties"]["score"]
    assert "maxLength" not in out["properties"]["label"]
    assert "default" not in out["properties"]["label"]
