"""Bridge job/poll async pattern (production-robust long turns).

/agent and /agent/approve must LAUNCH a background job and return a job_id at
once — never hold one HTTP request open for a minutes-long turn (which tripped
the surface fetch / host idle timeout and discarded the finished report). The
surface polls /agent/result. These pin the lifecycle with the worker stubbed
(no model calls).
"""

from __future__ import annotations

import inspect
import time

from fastapi.testclient import TestClient

import impactiq.server as srv


def _poll(client: TestClient, job_id: str, tries: int = 80) -> dict:
    for _ in range(tries):
        r = client.post("/agent/result", json={"job_id": job_id}).json()
        if r.get("job_status") != "running":
            return r
        time.sleep(0.05)
    raise AssertionError("job never left 'running'")


def test_agent_launches_job_then_result_done(monkeypatch):
    monkeypatch.setattr(
        srv, "_run_unified_agent",
        lambda req, user_assertion=None: {"text": "the answer", "status": "completed"},
    )
    client = TestClient(srv.app)
    launch = client.post("/agent", json={"request": "hi", "conversation": "c1"}).json()
    assert launch["job_status"] == "running"
    assert launch.get("job_id")            # returns a handle, NOT the result
    assert "text" not in launch            # the result is NOT delivered synchronously

    done = _poll(client, launch["job_id"])
    assert done["job_status"] == "done"
    assert done["result"]["text"] == "the answer"
    assert done["result"]["status"] == "completed"   # run_status preserved, not shadowed


def test_agent_job_captures_worker_error(monkeypatch):
    def boom(req, user_assertion=None):
        raise RuntimeError("kaboom in the pipeline")

    monkeypatch.setattr(srv, "_run_unified_agent", boom)
    client = TestClient(srv.app)
    job_id = client.post("/agent", json={"request": "x"}).json()["job_id"]
    res = _poll(client, job_id)
    assert res["job_status"] == "error"
    assert "kaboom" in res["detail"]


def test_result_unknown_job():
    client = TestClient(srv.app)
    r = client.post("/agent/result", json={"job_id": "does-not-exist"}).json()
    assert r["job_status"] == "unknown"


def test_approve_also_launches_a_job(monkeypatch):
    monkeypatch.setattr(
        srv, "_run_unified_agent_approve",
        lambda req, user_assertion=None: {"text": "resumed", "status": "completed"},
    )
    client = TestClient(srv.app)
    launch = client.post(
        "/agent/approve",
        json={"agent_name": "a", "agent_version": "1", "response_id": "r1",
              "approvals": {}, "pending": [], "user": "u"},
    ).json()
    assert launch["job_status"] == "running" and launch.get("job_id")
    done = _poll(client, launch["job_id"])
    assert done["job_status"] == "done" and done["result"]["text"] == "resumed"


# ── pins: the endpoints must stay thin launchers; the body lives in the worker ──


def test_agent_endpoint_is_a_thin_launcher():
    launcher = inspect.getsource(srv.unified_agent)
    assert "_launch_job(" in launcher
    assert "_run_unified_agent" in launcher
    # the real work (the agent turn) is NOT inline in the request handler
    assert "run_agent_turn" not in launcher
    worker = inspect.getsource(srv._run_unified_agent)
    assert "run_agent_turn" in worker
    # approve is launched the same way
    assert "_launch_job(" in inspect.getsource(srv.unified_agent_approve)
