"""Append-only audit log for the governance + write chain.

Every outbound send and every executed write lands here as one JSON line:
who confirmed what, on which evidence, with which platform change id. The
chain is queryable so an owner can later ask "what did ImpactIQ write on
this table this week, at whose hand, on what evidence?".

Current scope: local JSONL file (gitignored). A production deployment would
ship these to an immutable store; the *shape* of the record is the contract.
"""

from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path

AUDIT_LOG_PATH = Path("audit-log.jsonl")
_lock = threading.Lock()


def audit_log(event_type: str, payload: dict) -> str:
    """Append one audit event; returns the event id."""
    event_id = f"evt-{uuid.uuid4().hex[:12]}"
    record = {
        "event_id": event_id,
        "event_type": event_type,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        **payload,
    }
    line = json.dumps(record, ensure_ascii=False, default=str)
    with _lock:
        with AUDIT_LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    return event_id


def read_audit_log() -> list[dict]:
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
