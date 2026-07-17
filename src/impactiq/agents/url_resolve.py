"""Parse Power Apps / Dynamics 365 URLs into estate identifiers.

When a user can't name a component precisely ("the request type field",
"Admin task"), the fastest disambiguation is: *paste the URL you're looking
at*. Model-driven runtime and maker URLs encode the entity logical name,
record id, view id and form id - far more reliable than a display name.

Pure functions, no network. The agent calls these through the
``resolve_url`` tool; the parser itself is fully unit-tested offline.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, unquote, urlparse

# Maker-portal path forms, e.g.
#   https://make.powerapps.com/environments/<env>/entities/<logicalname>/...
#   .../tables/<logicalname>/columns/...
_MAKER_ENTITY_RE = re.compile(r"/(?:entities|tables)/([A-Za-z0-9_]+)")
_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _clean_guid(value: str | None) -> str | None:
    if not value:
        return None
    v = unquote(value).strip().strip("{}")
    return v if _GUID_RE.match(v) else None


def parse_powerapps_url(url: str) -> dict:
    """Extract estate identifiers from a Power Apps / Dynamics URL.

    Returns a dict with any of: ``entity_logical`` (the gold - the table's
    logical name), ``record_id``, ``view_id``, ``form_id``, ``pagetype``,
    ``app_id``, ``environment_id``, ``host``. Unknown keys are omitted.
    """
    out: dict[str, str] = {}
    if not url or not isinstance(url, str):
        return out
    url = url.strip()
    try:
        parsed = urlparse(url)
    except ValueError:
        return out
    if parsed.hostname:
        out["host"] = parsed.hostname

    # Query-string form (model-driven runtime: main.aspx?...etn=...&id=...).
    qs = parse_qs(parsed.query)

    def _first(key: str) -> str | None:
        vals = qs.get(key)
        return vals[0] if vals else None

    etn = _first("etn")
    if etn:
        out["entity_logical"] = etn.lower()
    if _first("pagetype"):
        out["pagetype"] = _first("pagetype")
    if _first("appid"):
        out["app_id"] = _clean_guid(_first("appid")) or _first("appid")
    rid = _clean_guid(_first("id"))
    if rid:
        out["record_id"] = rid
    vid = _clean_guid(_first("viewid"))
    if vid:
        out["view_id"] = vid
    fid = _clean_guid(_first("formid"))
    if fid:
        out["form_id"] = fid

    # Maker-portal path form (/environments/<env>/entities/<logical>).
    if "environments/" in parsed.path:
        m = re.search(r"/environments/([^/]+)", parsed.path)
        if m:
            out["environment_id"] = m.group(1)
    if "entity_logical" not in out:
        m = _MAKER_ENTITY_RE.search(parsed.path)
        if m:
            out["entity_logical"] = m.group(1).lower()

    return out


def find_url_in_text(text: str) -> str | None:
    """Pull the first http(s) URL out of a free-text message, if any."""
    if not text:
        return None
    m = re.search(r"https?://\S+", text)
    return m.group(0).rstrip(").,] ") if m else None
