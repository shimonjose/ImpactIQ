"""ImpactIQ eval harness — labelled scenarios + graders + scorecard.

The behavior pins (tests/test_behavior_pins.py) prove text EXISTS; this proves
the verdict is RIGHT. Two run modes (see evals/run.py):

* **mock** (CI, no tenant): feeds stubbed specialist findings + a draft report
  through the REAL verdict gate and grades the deterministic outcome — gate
  enforcement + the reasoning invariants. Gates merges cheaply.
* **live** (opt-in): runs the real multi-agent pipeline and grades the model's
  actual report (hard fields deterministically + an optional rubric LLM judge
  for the soft ones).
"""
