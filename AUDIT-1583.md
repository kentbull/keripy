# PR 1583 roster audit

PR https://github.com/WebOfTrust/keripy/pull/1583 is closed, unmerged (closed
2026-08-06). Its loadHabs omission remains in both habitat branches.

## Sources inspected

- KERIpy analysis/pr1583-rmids, based on the requested primary repository HEAD
  41ddbdcc1 (fix/tcp-messenger-outcomes-v1.2.15).
- KERIA analysis/pr1583-signify-rmids, based on tocks-config-compat commit
  06ca59bb. Tests use that branch's existing Python environment, whose KERIpy
  package reports version 1.2.14. Its actual loaded source was inspected.
- Freshly fetched WebOfTrust KERIpy main afd56a73d and v1.2.14 bab95c16e:
  source inspection confirms the reload omission. Main also retains the
  constructors' truthiness default. Upstream heads were not runtime-tested.

## Confirmed defects

1. Habery.loadHabs passes smids but omits persisted rmids for GroupHab and
   SignifyGroupHab. With one signer and three rotation members, a real
   database close/reopen produces one in-memory rotation member. The database
   still has three rotation members and the KEL still has three next digests.
   This affects differing rosters, not merely wider ones: ordering also matters.
   KLI multisig interaction and delegation-confirm notification recipients read
   the in-memory roster and consequently omit rotation-only members.
2. Both constructors use `rmids or smids`. An explicit empty rotation roster
   becomes the signing roster and is persisted incorrectly at inception,
   despite the actual event having no next digests. The KERIA members endpoint
   consequently reports a rotation member for the tested non-rotatable event.
   Passing rmids through loadHabs alone cannot fix this.

## KERIA impact boundary

GroupMemberCollectionEnd reads db.signingMembers/db.rotationMembers. In the
real SignifyGroupHab reopen reproduction it still returned all three correct
rotation members while the habitat object's rmids contained only one.
The group rotation endpoint requires request smids/rmids and forwards those
to hab.rotate; it does not derive the new roster from the reloaded rmids.
Thus the restart defect is present in KERIA's dependency, but automatic
Signify-client membership loss was not established. No full Signify client or
distributed multisig/delegation workflow was run.

## Separate rotation default

KLI GroupMultisigRotate.rotateDo defaults missing rmids to its selected smids,
not the existing rotation roster (rotate.py lines 124-128). It builds next
digests from that roster and passes it explicitly to ghab.rotate. This is
independent of restart and survives PR 1583. Whether changing the CLI default
is desired requires a separate behavior decision; callers preserving a wider
roster must explicitly supply it today. Threshold validation and eventual
event acceptance still apply: restart alone never changes the committed KEL.
The stock group delegation-confirm path explicitly declines anchoring via
rotation; the PR's production EstOnly claim is not demonstrated by that path.

## Reproductions and candidate checks

Added tests/app/test_pr1583_audit.py in each analysis worktree. Tests use
pytest-owned persistent database directories and temporary configuration.
Signify events and signatures are supplied from a separate edge Habery.

Run from either analysis worktree:

```sh
PYTHONPATH=src /Users/kbull/enc/keri/worktrees/keria/tocks-config-compat/.venv/bin/python -m pytest -q tests/app/test_pr1583_audit.py
```

The primary KERIpy venv lacks pytest, so the KERIA environment supplied the
runner/dependencies; PYTHONPATH selects the KERIpy analysis source for its tests.

| Candidate | GroupHab | SignifyGroupHab / KERIA |
| --- | --- | --- |
| Unmodified | 2 fail | 2 fail |
| PR reload forwarding only | 1 pass, 1 fail | 1 pass, 1 fail |
| Forwarding plus None-only constructor default | 2 pass | 2 pass |

Candidate checks replaced functions only in the test process using
/tmp/pr1583_candidate_check.py; no production source edits were made.
These focused tests establish the defects and narrow fixes, not full-suite
or distributed-protocol readiness. The committed history is unchanged.
