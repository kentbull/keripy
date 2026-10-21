# Additive community-component parity

The qualified baseline remains KERIpy `64e14e08` / Dolly `8da5d71`. The new
community profile is additive: original KLI commands and tests remain supported.
The execution plan lives in ENCTX as
`plans/keri/acdc-v2/additive-community-component-parity-plan.md`.

## Shared evidence composition

`keri.app.evidencing` owns concrete native evidence processors, KRAM maintenance,
accepted replay and dependency retry. `keri.app.evidence_httping` binds existing
Falcon requests to that authentication and provides a health response. Neither
module constructs service routes or chooses a publisher/reader policy.

The original `keri.app.registrar.serving.Context` remains an application subclass
that binds its existing routes and allowlists. Its helper import paths remain
available. Observer, native IPEX command composition and public-evidence commands
consume the neutral composition directly. Existing observer keyword allowlists
remain application-owned for compatibility. Dolly may keep its original import
until its dependency pin is updated; no extra runtime dependency is introduced.

### Lineage and changed-unit record

This is a local Codex refactor under Kent's additive community-component request,
not a new protocol design. The donor is the qualified `64e14e08` implementation
of `src/keri/app/registrar/serving.py`; that module records its KF registrar
ancestry. Original notices and the prior branch-wide lineage remain applicable.

| Destination / changed unit | Origin and local delta |
|---|---|
| `evidencing.KEL_DEPENDENCIES`, `ServiceConfig.__init__/get`, `signedQuery` | Moved unchanged from the registrar; AST equality checked. |
| `evidencing.EvidenceContext.__init__` | Original registrar constructor with HTTP routes and role allowlists separated; same processors, store, pruner and escrow owner. |
| `EvidenceContext.ingest`, `_kelPending`, `registries`, `clone`, `escrowDo`, `close` | Original registrar methods moved unchanged; AST equality checked. |
| `evidence_httping.authenticate`, `HealthEnd.on_get` | Moved unchanged; exact request validation, errors and health semantics retained. |
| `registrar.serving.Context.__init__` and module imports | New concrete application composition; legacy helper exports and setup/HTTP endpoints retained. |
| `observer.serving.Context.__init__` and imports | Neutral evidence base; previously accepted publisher/observer keyword fields stay on the application. |
| `cli.common.native_exchange` and `public_evidence` imports/construction | Use neutral evidence context; no command or message contract changed. |
| `test_native_services.test_resolved_wrong_anchor_locator_is_not_dropped_at_service_intake` | Existing real false-anchor/replay regression runs through both neutral and legacy application entry points. |
| This document | Locally authored change/provenance record, not an upstream attribution claim. |

The original service, pruning, IPEX, public-evidence and group tests are the
regression boundary. Exact run results will be appended after completion;
constructing a neutral context or creating community forks alone does not
qualify the new external-component workflow.

Validation on 2026-10-21: the installed Linux wheel passed 36 focused tests
across `test_native_services`, `test_native_service_pruning`,
`test_native_ipex_cli`, `test_public_evidence_cli`, `test_native_groups` and
`test_native_group_pruning` (61.85 seconds; existing pysodium deprecation).
Source was copied into the image and LMDB stayed in named volumes. This closes
the composition regression gate, not external service or UI acceptance.

### Shared observation composition

`evidence_observing.Observation`, `ObservationBaser`, `RegistrarPuller`, and
`ObservedEvidence.observe/close` move from `app.observer.serving` at 4b1078e0.
`evidence_querying.QueryEnd` moves from the same source. AST comparison confirms
all those complete classes/methods are unchanged. `ObservedEvidence.__init__`
retains evidence, freshness and persistence configuration while the compatible
`observer.serving.Context.__init__` retains reader/legacy allowlists and routes.
This is a local composition decision; original donor lineage remains
kf-observer d6368aef, as recorded above. No query can schedule acquisition.

This review unit exceeds the nominal line target because it moves a cohesive
observation/polling/query implementation with its docstrings, preserving legacy
imports and behavior. It also removes surplus EOF blank lines from the previous
shared modules. The 21 installed-core service, pruning and public-evidence CLI
tests pass after extraction. Whole-profile qualification remains outstanding.
