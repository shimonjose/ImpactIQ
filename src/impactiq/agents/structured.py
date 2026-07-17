"""Native structured-output helpers.

Turns a pydantic model's JSON schema into the OpenAI strict-mode subset and
wraps it as a ``PromptAgentDefinition`` text format, so the platform guarantees
schema-conformant final output instead of us scraping JSON from prose.

Gated by ``IMPACTIQ_STRUCTURED_OUTPUT`` at the call sites; ``extract_json_block``
+ the orchestrator-plan salvage stay as the fallback, so flag-off is byte-for-byte
the current behaviour and a non-conforming edge never crashes the turn.

Strict-mode constraints: every object needs ``additionalProperties:false`` and
all its properties in ``required``; the numeric/string/array bound keywords below
are unsupported and must be stripped (pydantic emits ``minimum``/``maximum`` for
``Field(ge=, le=)``). ``OrchestratorPlan`` has none of these and is a clean fit;
the full ``ImpactReport`` is NOT (RiskOut bounds + a loose ``generated_artifact``
dict), which is why only the orchestrator is wired.
"""

from __future__ import annotations

import os
from typing import Any

# Keywords the OpenAI strict-mode JSON-schema subset rejects, plus annotation-
# only keys (`default`/`title`) strict validation also trips on.
_STRICT_STRIP = frozenset(
    {
        "minimum", "maximum", "multipleOf", "exclusiveMinimum", "exclusiveMaximum",
        "minLength", "maxLength", "pattern", "format",
        "minItems", "maxItems", "uniqueItems", "minContains", "maxContains",
        "default", "title",
    }
)


def strictify(node: Any) -> Any:
    """Recursively transform a pydantic JSON schema into the strict-mode subset:
    drop unsupported keywords, force ``additionalProperties:false`` and mark every
    property ``required`` (nullability rides on the schema's own anyOf/[type,null]
    - e.g. an optional ``NodeRef`` is already ``anyOf:[{$ref},{type:null}]``)."""
    if isinstance(node, dict):
        out = {k: strictify(v) for k, v in node.items() if k not in _STRICT_STRIP}
        if out.get("type") == "object" and "properties" in out:
            out["additionalProperties"] = False
            out["required"] = list(out["properties"].keys())
        return out
    if isinstance(node, list):
        return [strictify(x) for x in node]
    return node


def structured_output_enabled() -> bool:
    raw = (os.environ.get("IMPACTIQ_STRUCTURED_OUTPUT") or "").strip().lower()
    return raw in ("1", "on", "true", "yes", "enforce")


def schema_text_format(name: str, model_cls: Any, *, strict: bool = True) -> Any:
    """Build a ``PromptAgentDefinitionTextOptions`` json_schema format from a
    pydantic model class. The azure model import is lazy so this module stays
    import-safe where the SDK isn't needed (tests of ``strictify`` etc.)."""
    from azure.ai.projects.models import (
        PromptAgentDefinitionTextOptions,
        TextResponseFormatJsonSchema,
    )

    schema = strictify(model_cls.model_json_schema())
    return PromptAgentDefinitionTextOptions(
        format=TextResponseFormatJsonSchema(
            type="json_schema", name=name, schema=schema, strict=strict,
        )
    )
