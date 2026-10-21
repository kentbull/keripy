# Refactor qualification status

The `e45f57fbf524ab0a9739baa4786dcbc5e6632ba2` branch is the R&D
foundation, not yet the qualified TypeScript behavioral reference. The current
work retains its useful protocol machinery while closing the adversarial review,
optional-custody, standalone-Dolly, and operator-workflow gates.

## Baseline

- Execution date: 2026-10-20 (America/Denver).
- Upstream `WebOfTrust/keripy:main`, checked remotely at execution start:
  `c7e74adc3129ba36302db32e58056560b0927424`.
- Integration branch `kentbull/keripy:v2-e2e`, clean at execution start:
  `e45f57fbf524ab0a9739baa4786dcbc5e6632ba2`; remote matched.
- `kentbull/dolly` was empty when inspected and cloned. Dolly application code
  will move there; no Dolly application compatibility package remains in KERIpy.
- Source/state qualification uses copied Linux source and Docker-managed LMDB
  volumes. No host bind mount is required by either test runner.

## Completed evidence

| Review unit | Validation | Result |
|---|---|---|
| Linux-owned test source and installed KERIpy wheel | `V2_TEST_IMAGE=keripy-v2-refactor:runner V2_TEST_VOLUME=keripy-v2-refactor-runner scripts/v2-e2e/check.sh tests/core/test_threshold_distinct_indices.py` | 5 passed |
| Released-peer runner without host mounts | `V2_MATRIX_IMAGE=keripy-v2-refactor:runner LEGACY_SKIP_BUILD=1 scripts/v2-e2e/legacy-peers/check.sh` | 2 passed, actual 1.2.14/1.3.6 peers |

These targeted checks qualify the runner change, not the complete refactor.
The historic 799-test result is not new evidence for the current changes.

## Remaining acceptance

R1–R8 repairs, optional custody H1–H8, standalone Dolly/transport D1–D4,
dual-version KLI and six independent Bash scenarios C1–C3, provenance P1,
human-reviewable commits Q2, and documentation Q3 remain open until their
concrete evidence is recorded. The provenance inventory is incomplete until
all prior branch contributions and current edits are reconciled.
