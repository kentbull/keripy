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

### Actual KF process profile

The scenario `common.sh` service selector, `run-linux.sh` image composition and
new `Dockerfile.kf` are local integration work on the existing qualified Bash
harness. Default `kli` execution is preserved; `SCENARIO_SERVICE_PROFILE=kf`
launches actual installed fork binaries with explicit full-evidence flags.
The only extra port is the registrar's separate local admin API. Three witness
processes and quorum two remain unchanged. Fork revisions/dirty flags and wheel
hashes join the existing result manifest.

Development S1 (full holder, graduated HTTP) and S2 (partial holder, onward TCP)
passed with two Dolly hooks each using registrar 7b77c08 and observer 27a7e0f.
These runs used an uncommitted harness and do not close clean qualification,
hosted-witness or Locksmith acceptance gates.

### Hosted witness authorization through KLI

`cli.common.witness_authing.readWitnessAuth` is a local narrow adapter from an
explicit JSON file to the existing `Receiptor` authorization map. Native author
options/run/anchor and rotate parser/handler/doer pass these short-lived headers
without persisting TOTP seeds or changing ordinary presentation. Native authoring
rejects unrelated witness IDs and explicitly rejects this new option for groups;
existing group workflows retain their previous behavior.

The root URL fix in `witness.authenticate.AuthDoer.authDo` adapts the existing
upstream command: strip its trailing slash before appending `/aids`, preventing
HIO from interpreting `//aids` as another host. The actual hosted onboarding
run reproduced that failure before correction.

Fifteen focused native CLI/group/pruning tests pass. A development S1 story also
passes using the actual hosted witness, registrar and observer binaries, including
TOTP registration, a quorum-two rotation, native issuance and two Dolly hooks.
This checks the real authorization path; final clean qualification remains open.

### Hosted scenario composition

`scenarios/hosted.sh` and `hosted.py`, the witness profile branches in `common.sh`
and `run-linux.sh`, `Dockerfile.hk` and result mapping are local test integration.
They reuse the existing witness-hk boot/registration API and KLI rotation; no
new provider protocol or bypass is introduced. Three processes retain quorum
two, with the provider's per-controller witness identities and pre-issuance
onboarding rotation explicitly recorded. The original witnessed-inception
scenario profile remains supported.

Development S1 passed against witness-hk cafe3f2, registrar 7b77c08, observer
27a7e0f and the authored KLI authorization changes. This result has two actual
Dolly hooks, but does not close all-six/released-peer/restart/clean-artifact gates.

`EvidenceProcessor` separates borrowed verification from `EvidenceContext`'s
service lifecycle. Its ingestion, pending classification and export methods are
moved unchanged from the context at `9ca869f6` (AST compared). Callers supply
strict Kevery and Rever instances for one Habery. The adapter opens no store,
creates no Kramer/pruner, and has no scheduler or close method; the vault or
service remains the lifecycle owner. This composition boundary is a local
implementation decision needed by the external wallet, not a protocol change.
Nineteen installed tests cover borrowed ownership and existing service
acceptance/pruning, including restart and cancellation.

`credential_disclosing.registryProof` extracts event-opening composition from
`ExchangeDoer.registryOrigin` at `a6539208`. It accepts exact retained openings
and an optional explicit derivation callable; it does not open custody or expand
credential attributes. The CLI retains its file loading and bound-coordinate
selection. Missing history now raises a precise configuration error. This local
composition change lets Locksmith reuse the qualified proof selection without
importing CLI code. Twenty-nine installed native CLI, wallet and custody tests
pass, including retained presentation and supplied/derived refresh boundaries.

### Order-independent hosted quorum and restart

`Receiptor._collectReceipts` was extracted unchanged at `d74c83f1` from
`Receiptor.receipt` at `325f2507`. The subsequent local scheduling change sends
all receipt requests before polling responses, allowing the ordinary habitat
parser to verify later witnesses while an earlier endpoint is offline. It does
not change signature verification, quorum policy or the caller's deadline.
`receipt` now releases its client Doers on cancellation as well as completion.
This is local corrective design, not an upstream protocol requirement invented
by this fork. Catch-up for newly added witnesses and completion of all-witness
receipt propagation retain their existing behavior.

The dedicated `hosted-quorum-restart.sh` uses three real provider processes and
quorum two. It stops the first configured witness, successfully anchors a
registry with the remaining two, then stops a second and checks refusal. It
restarts that provider against its retained store and successfully retries the
same pending registry inception, then checks the first provider's original OOBI.
The sequential collector failed this test before the change. The development
composition passes afterward; five focused installed-wheel receipt tests also
pass, including genuine v1/v2 signatures and cancellation cleanup. Final clean
artifact qualification remains separate.

### Released HTTP media type

Actual isolated KERIpy 1.2.14 and 1.3.6 peers exposed a 406 before receipt
verification: their `app.httping.CESR_CONTENT_TYPE` is
`application/cesr+json`, whereas this core emits `application/cesr`.
`parseCesrHttpRequest` now accepts both established names for its existing
JSON-body/attachment-header contract. Outbound framing and the required JSON
and attachment checks remain unchanged. This is a local compatibility adaptation
of the upstream parser, grounded in those released source distributions.
All six HTTP helper tests pass; the hosted released-peer matrix subsequently
verifies registration, unauthorized refusal and authentic indexed receipts in
both unmodified released interpreters. Its harness lives in witness-hk.
