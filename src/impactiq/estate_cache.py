"""Process-level TTL cache for the estate snapshot.

Every smart turn used to rebuild the estate (Dataverse metadata + flows +
roles reads → normalized fragment) from scratch — tens of seconds before the
model saw a single token. The snapshot is cached here per (org, solution) and
reused within the TTL, so follow-up questions start reasoning immediately.

Why a local TTL cache and not something Microsoft-hosted: the estate is a
DERIVED artifact (three connectors' output merged + normalized) — no turnkey
service caches it for us. Dataverse's native mechanism for client-side
metadata caches is the ``RetrieveMetadataChanges`` delta-sync API (keyed by a
ClientVersionStamp); that is the production upgrade path for precise
invalidation. For interactive use a bounded staleness window is the right
trade: worst case, an answer reflects the estate as of ``TTL`` ago — and the
walk/enrichment reads that ground bounded writes always run live against
Dataverse, so the cache can never make a write less safe.

Thread-safety: misses may race (two concurrent turns both rebuild — harmless,
last write wins); hits are lock-protected reads.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any

from .connectors import EstateScope, build_estate, clear_cache

# 10 minutes by default — long enough that an active conversation never
# rebuilds, short enough that schema work shows up without a restart.
TTL_SECONDS = float(os.environ.get("ESTATE_CACHE_TTL_SECONDS", "600"))

_lock = threading.Lock()
_cache: dict[tuple[str, str], tuple[Any, Any, float]] = {}


def get_estate_cached(
    dv_client: Any, settings: Any, solution_name: str
) -> tuple[Any, Any]:
    """Return (scope, fragment), from cache when fresh, else a live rebuild.

    The caller's ``dv_client`` is only used on a miss; cached hits don't touch
    Dataverse at all.
    """
    key = (str(getattr(settings, "dataverse_url", "") or ""), solution_name or "")
    now = time.monotonic()
    with _lock:
        hit = _cache.get(key)
    if hit is not None and (now - hit[2]) < TTL_SECONDS:
        return hit[0], hit[1]
    started = time.perf_counter()
    # use_cache=False is load-bearing: THIS module is the estate cache now (it
    # owns the TTL and invalidate()). build_estate's own process-global
    # _FRAGMENT_CACHE has no TTL and is never expired, so if we let it serve a
    # miss here, a rebuild after TTL expiry — or right after invalidate() —
    # would get the SAME stale fragment straight back, making both our expiry
    # and invalidate() silent no-ops. Forcing a genuine rebuild keeps this
    # layer's freshness contract real.
    scope, fragment = build_estate(
        dv_client, EstateScope(solution_name=solution_name), use_cache=False
    )
    print(
        f"(estate built in {time.perf_counter() - started:.1f}s — cached for "
        f"{TTL_SECONDS:.0f}s)",
        flush=True,
    )
    with _lock:
        _cache[key] = (scope, fragment, time.monotonic())
    return scope, fragment


def invalidate(solution_name: str | None = None) -> None:
    """Drop cached snapshots (all, or one solution's across orgs)."""
    with _lock:
        if solution_name is None:
            _cache.clear()
        else:
            for key in [k for k in _cache if k[1] == (solution_name or "")]:
                del _cache[key]
    # Also clear build_estate's lower, TTL-less _FRAGMENT_CACHE. Without this,
    # the next miss rebuilds via build_estate which — left to its own cache —
    # would hand back the stale fragment, making this invalidate() a no-op.
    # That cache is keyed by scope.cache_key (not org/solution), so a
    # solution-scoped invalidation can't target one entry; we clear it
    # wholesale and let it repopulate lazily on the next build. Over-clearing
    # is harmless; under-clearing would resurrect stale data.
    clear_cache()
