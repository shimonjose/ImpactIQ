# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** via GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository (Security → Report a vulnerability). Do not open a public
issue for security reports.

Please include: the affected file/endpoint, reproduction steps, and the
impact you believe is possible. You should receive an acknowledgement within
a few days.

## Scope

Impact IQ is a bridge (Python/FastAPI) + Teams Custom Engine Agent (TypeScript)
that reads a Power Platform estate and performs narrowly-bounded, explicitly
confirmed writes. Reports are especially valuable for anything that could:

- bypass the confirm-before-write gates (`/action/remediate`,
  `/action/sandbox_fix`, `/action/resubmit_run`) or the owner-bound
  one-time proposal store (`src/impactiq/proposals.py`),
- cause an action to execute under the wrong user identity (On-Behalf-Of
  handling, `src/impactiq/identity.py`, `src/impactiq/builder/gate.py`),
- steer agent behaviour through retrieved content (prompt injection into
  tool results), or
- leak one user's data or pending state to another.

## Security model (summary)

- **Two identities by scope**: a read-only service identity reads structure;
  a delegated per-user (OBO) identity reads content and performs writes.
- **No LLM in the write path**: models propose typed artifacts; a
  deterministic gate validates; the user confirms; the server executes one
  typed, version-pinned (ETag) Web API call.
- **Owner-bound, one-time proposals**: every offered mutation is stored
  server-side, bound to the proposing user's tenant + object id, consumed
  atomically once, after authorization.
- **Fail closed**: a hosted bridge refuses to start without its auth key;
  mutation proposals are withheld when the verifier cannot confirm them.
