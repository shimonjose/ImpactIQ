"""Append-only, tamper-evident audit log for the governance + write chain.

Every outbound send and every executed write lands here as one JSON line:
who confirmed what, on which evidence, with which platform change id. The
chain is queryable so an owner can later ask "what did ImpactIQ write on
this table this week, at whose hand, on what evidence?".

Tamper-evidence: each record carries the hash of the record before it (``prev``)
and its own hash (``hash``) over its canonical content. Removing, reordering, or
editing any record breaks the chain at that point, which :func:`verify_audit_log`
detects and reports rather than silently accepting.

Storage: a local JSONL file by default (gitignored). When ``IMPACTIQ_AUDIT_SINK_URL``
is set, each record is ALSO best-effort mirrored to that endpoint, so an operator
can forward the chain to an append-only / immutable (WORM) store off the box. The
local file remains the source of the running hash.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx

AUDIT_LOG_PATH = Path("audit-log.jsonl")
_lock = threading.Lock()

# The hash of the most recently written record, chaining the next one to it.
# Genesis (empty log) links to a fixed sentinel so the first record is still
# covered by the chain. Tracked per log path (the path is swappable in tests),
# lazily seeded from that file's tail on first write.
_GENESIS = "0" * 64
_last_hash_by_path: dict[str, str] = {}

# Optional off-box mirror (best-effort). Point it at an append-only / immutable
# collector; a failure here never blocks the audited action.
_SINK_URL = os.getenv("IMPACTIQ_AUDIT_SINK_URL", "").strip()


def _record_hash(record: dict) -> str:
    """SHA-256 over the record's canonical JSON, excluding its own hash."""
    body = {k: v for k, v in record.items() if k != "hash"}
    blob = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def _seed_last_hash() -> str:
    """Return the running hash for the current log path, seeding it once from
    that file's tail."""
    key = str(AUDIT_LOG_PATH)
    cached = _last_hash_by_path.get(key)
    if cached is not None:
        return cached
    last = _GENESIS
    if AUDIT_LOG_PATH.exists():
        for line in AUDIT_LOG_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                prior = json.loads(line)
            except json.JSONDecodeError:
                continue
            h = prior.get("hash")
            if h:
                last = h
    _last_hash_by_path[key] = last
    return last


def _mirror(line: str) -> None:
    if not _SINK_URL:
        return
    try:
        httpx.post(
            _SINK_URL,
            content=line.encode("utf-8"),
            headers={"Content-Type": "application/json"},
            timeout=5,
        )
    except Exception:  # noqa: BLE001 - the mirror is best-effort, never blocking
        pass


def audit_log(event_type: str, payload: dict) -> str:
    """Append one tamper-evident audit event; returns the event id."""
    event_id = f"evt-{uuid.uuid4().hex[:12]}"
    with _lock:
        prev = _seed_last_hash()
        record = {
            "event_id": event_id,
            "event_type": event_type,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            **payload,
            "prev": prev,
        }
        record["hash"] = _record_hash(record)
        line = json.dumps(record, ensure_ascii=False, default=str)
        with AUDIT_LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
        _last_hash_by_path[str(AUDIT_LOG_PATH)] = record["hash"]
    _mirror(line)
    return event_id


def read_audit_log() -> list[dict]:
    """Return every audit record. Malformed lines are skipped (the chain is the
    integrity check; use :func:`verify_audit_log` to detect tampering)."""
    if not AUDIT_LOG_PATH.exists():
        return []
    out = []
    for line in AUDIT_LOG_PATH.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def verify_audit_log() -> tuple[bool, list[str]]:
    """Verify the hash chain end to end. Returns (ok, issues); each issue names
    the record index where the chain is inconsistent (a broken ``prev`` link, a
    recomputed hash that no longer matches, or an unparseable line)."""
    issues: list[str] = []
    if not AUDIT_LOG_PATH.exists():
        return True, issues
    prev = _GENESIS
    for i, raw in enumerate(AUDIT_LOG_PATH.read_text(encoding="utf-8").splitlines()):
        raw = raw.strip()
        if not raw:
            continue
        try:
            record = json.loads(raw)
        except json.JSONDecodeError:
            issues.append(f"record {i}: unparseable line")
            continue
        if record.get("prev") != prev:
            issues.append(f"record {i}: prev-hash does not match the previous record")
        if record.get("hash") != _record_hash(record):
            issues.append(f"record {i}: content hash does not match (record altered)")
        prev = record.get("hash") or prev
    return (not issues), issues
