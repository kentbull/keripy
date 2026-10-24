# Shared native application capabilities

These additive library and KLI capabilities remain product-owned. Source lineage
and local implementation decisions below do not assert universal conformance.

## Shared evidence composition

`keri.app.evidencing` owns concrete native evidence processors, KRAM maintenance,
accepted replay and dependency retry. `keri.app.evidence_httping` binds existing
Falcon requests to that authentication and provides a health response. Neither
module constructs service routes or chooses a publisher/reader policy.

The original `keri.app.registrar.serving.Context` remains an application subclass
that binds its existing routes and allowlists. Its helper import paths remain
available. Observer, native IPEX command composition and public-evidence commands
consume the neutral composition directly. Existing observer keyword allowlists
remain application-owned for compatibility. Consumers import these concrete library owners; no experiment runtime dependency
is introduced.

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

### Shared observation composition

`evidence_observing.Observation`, `ObservationBaser`, `RegistrarPuller`, and
`ObservedEvidence.observe/close` move from `app.observer.serving` at 4b1078e0.
`evidence_querying.QueryEnd` moves from the same source. AST comparison confirms
all those complete classes/methods are unchanged. `ObservedEvidence.__init__`
retains evidence, freshness and persistence configuration while the compatible
`observer.serving.Context.__init__` retains reader/legacy allowlists and routes.
This is a local composition decision; original donor lineage remains
kf-observer d6368aef, as recorded above. No query can schedule acquisition.

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

### Borrowed verification and registry proof composition

`EvidenceProcessor` separates borrowed verification from `EvidenceContext`'s
service lifecycle. Its ingestion, pending classification and export methods are
moved unchanged from the context at `9ca869f6` (AST compared). Callers supply
strict Kevery and Rever instances for one Habery. The adapter opens no store,
creates no Kramer/pruner, and has no scheduler or close method; the vault or
service remains the lifecycle owner. This composition boundary is a local
implementation decision needed by the external wallet, not a protocol change.
Component regressions cover borrowed ownership and service acceptance/pruning,
including restart and cancellation.

`credential_disclosing.registryProof` extracts event-opening composition from
`ExchangeDoer.registryOrigin` at `a6539208`. It accepts exact retained openings
and an optional explicit derivation callable; it does not open custody or expand
credential attributes. The CLI retains its file loading and bound-coordinate
selection. Missing history now raises a precise configuration error. This local
composition change lets Locksmith reuse the qualified proof selection without
importing CLI code. Native CLI, wallet and custody regressions cover retained presentation and
supplied/derived refresh boundaries.

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
both unmodified released interpreters. The external harness is owned by the independent experiment repository.

### Exact bound-event selection

`credential_disclosing.boundEvent` extracts the existing `Wallet.boundEvent`
public-evidence lookup at aef3013d. The wallet method remains a compatibility
adapter. GUI and headless applications can select the same exact accepted,
fully witnessed issuee event without constructing a wallet or loading custody.
The historical-reference validation is unchanged; authoring a new bound update
still separately requires the known current issuee head. This is a local
separation-of-concerns extraction, not a new protocol or timing rule.

## Later source-review index

The [community lineage supplement](community-lineage.md) maps changed symbols,
moved predecessors and local decisions through 3e978775. Runtime qualification
remains pinned separately; documentation-only successors do not change that pin.

## Experiment ownership

Cross-repository recipes, external acceptance scenarios and dated evidence are
owned by the independent `keri-v2` experiment repository. They are not required
to run this component. [Pre-extraction record](https://github.com/kentbull/keripy/blob/81964a69e0dd9897c37654e80bb2d9cc7b6e2934/docs/v2-e2e/community-parity.md) preserves the
historical source and execution scope. The extraction changes ownership only;
runtime dependencies and verification contracts remain unchanged.
