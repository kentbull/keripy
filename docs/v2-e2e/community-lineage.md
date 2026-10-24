# Community integration lineage supplement

This index covers changes after the earlier `c380866b` source audit through
`3e9787750adc0b09661829882a0c82a2de560572`. The runtime qualification uses
`993b58266992b786d044fd3938e114a19d76f62f`; the later commit changes docstrings
only, with executable AST equality checked. The earlier
[lineage inventory](lineage-inventory.md) and machine ledger retain the preceding
branch's author/source evidence. They are bounded historical snapshots, not a
claim that later work was already reviewed.

The [finite comparison](https://github.com/kentbull/keripy/compare/c380866b16066a0cd00f562c4026e0d3f5a09a05...3e9787750adc0b09661829882a0c82a2de560572)
records Kent Bull as Git author. These changes were implemented with Codex under
Kent's direction. Git authorship is evidence of recorded contribution, not proof
of sole invention, endorsement or liability. Inherited protocol primitives
retain their upstream history; no original personal attribution is invented
where the source evidence does not establish one.

## Shared application extraction

These modules relocate already qualified application behavior so independent
components can compose it. The extractions precede new application adapters;
they do not introduce a second verifier or accepted-state writer.

| Current symbols | Concrete predecessor and local delta |
|---|---|
| `evidencing.ServiceConfig`, `__init__`, `get`; `signedQuery` | `registrar.serving` at `64e14e08`. Moved in `4b1078e0`; service-facing imports remain compatible. |
| `evidencing.EvidenceContext`, `__init__`, `ingest`, `registries`, `clone`, `escrowDo`, `close` | Registrar `Context` at `64e14e08`. `4b1078e0` separates shared evidence/storage lifecycle from routes and publisher policy. |
| `evidencing.EvidenceProcessor`, `__init__`, `ingest`, `_kelPending`, `registries`, `clone` | `EvidenceContext` at `9ca869f6`; moved unchanged in `7671c088` with AST comparison. New constructor borrows existing Kevery/Rever instead of opening stores, scheduling or owning close. |
| `evidence_httping.authenticate`; `HealthEnd`, `on_get` | Registrar adapter at `64e14e08`, moved in `4b1078e0`. Allowlists are application policy; KRAM remains the request verifier. Health reports availability only. |
| `evidence_observing.Observation`; `ObservationBaser`, `reopen` | Observer at `4b1078e0`, moved in `ae144adb`. Fields retain source, completed observation and exact accepted heads; storage constants remain inherited operational choices. |
| `evidence_observing.ObservedEvidence`, `__init__`, `observe`, `close` | Observer `Context` observation methods at `4b1078e0`, moved in `ae144adb`. Evidence and observation lifecycle remain composed explicitly. |
| `evidence_observing.RegistrarPuller`, `__init__`, `pollDo` | Observer puller at `4b1078e0`, moved in `ae144adb`; independent scheduling and cancellation retained. A query never triggers acquisition. |
| `evidence_querying.QueryEnd`, `__init__`, `on_post` | Observer endpoint at `4b1078e0`, moved in `ae144adb`; exact current source/head/observation checks remain unchanged. |
| `registrar.serving.Context`, `__init__`; `observer.serving.Context`, `__init__` | Existing concrete service owners now compose the shared modules. Removed definitions in these files have the exact successors above; compatible imported names remain available. |
| `credential_disclosing.registryProof` | `ExchangeDoer.registryOrigin` at `a6539208`, extracted in `8a86f16b`. New narrow contract accepts retained openings and an optional derivation callable; custody/file loading stays with the caller. |
| `credential_disclosing.boundEvent`; `credentialing.Wallet.boundEvent` | Wallet lookup at `aef3013d`, extracted in `993b5826`; Wallet retains a delegating compatibility method. It verifies an explicit accepted, fully witnessed historical issuee event. New authoring's current-head requirement remains separate. |

The earlier lineage ledger links registrar/observer ideas to pinned KF sources
and their recorded contributors. Extraction does not create a new claim of
original authorship for those inherited ideas.

## Hosted witness and transport changes

| Symbols / resources | Source and local decision |
|---|---|
| `agenting.Receiptor.receipt`, `_collectReceipts` | Existing upstream receipt orchestration. `d74c83f1` first extracts collection unchanged from `325f2507`; `71b6a366` then sends requests before polling and closes clients on cancellation. This local scheduling repair prevents an offline first endpoint from blocking an available quorum. Verification and threshold rules remain core-owned. |
| `httping.parseCesrHttpRequest` | Existing upstream parser plus local compatibility patch `64b5c6af`. Actual released KERIpy 1.2.14/1.3.6 source and peer runs establish `application/cesr+json`; the current `application/cesr` remains supported. No relaxed JSON/attachment requirement is introduced. |
| `native_exchange.Intake.on_put` alias | `7ebddb92` accepts StreamPoster's existing PUT at the same native intake root. It delegates to the existing POST handler and does not duplicate intake verification. |
| `witness_authing.readWitnessAuth` | New local operator-file adapter in `d5d26e04`, based on the existing hosted witness `Witness-Authorization` contract. Preserves exact code/timestamp pairs; no invented authentication protocol. |
| `rotate.rotate`, `RotateDoer.__init__`, `rotateDo`; parser additions | Existing KLI rotation adapted in `d5d26e04` to carry explicit hosted witness authorization into receipt collection. Existing rotation/receipt ownership remains. |
| `native.options`, `NativeAuthor.__init__`, `anchor`, `run`; `vc/registry/advance` parser | Local flag/configuration plumbing in `d5d26e04` and `a6539208`. The issuer selects auth data explicitly; native authoring remains the existing domain owner. |
| `public_evidence.Request.run`, `Advance.run` | Existing signed service request/update adapters now pass hosted authorization to receipt collection. No new source-freshness or KRAM time condition. |
| `native_exchange.ExchangeDoer.run`, `registryOrigin`, nested `derive` | Hosted authorization plus shared proof selection; CLI owns explicit opening files and bound coordinates. Core `registryProof` owns common selection. |
| `witness.authenticate.AuthDoer`, `__init__`, `authDo` | Existing upstream registration. `d5d26e04` normalizes the root URL before appending `/aids`, avoiding a network-path reference. `3e978775` corrects the inherited misleading credential-export docstring; this command outputs private TOTP provisioning material. |

## Component regressions

Changed tests in `test_agenting`, `test_evidence_processor`, `test_httping`,
`test_native_ipex_transport` and `test_native_services` are local regressions.
They use real signatures, existing core verification, cancellation and restart
boundaries; they are not claims of external code authorship. The clean installed
qualification and UI screenshots are separate execution evidence.

## Review scope

All current production Python class/function/method changes since `c380866b`
were enumerated with AST comparison, including constructors and nested helpers.
Moved methods and deleted predecessor definitions are mapped above; module
imports, parser options, fields and aliases follow their containing entries.
Changed methods have purpose/input/lifecycle contracts, with the final missing
class descriptions and witness registration correction in `3e978775`.

This supplement does not replace upstream Git history or the preceding detailed
ledger. It records bounded adaptation evidence, separates local design from
protocol requirements and leaves uncertain original invention unassigned.

## Experiment ownership

Cross-repository recipes, external acceptance scenarios and dated evidence are
owned by the independent `keri-v2` experiment repository. They are not required
to run this component. [Pre-extraction record](https://github.com/kentbull/keripy/blob/81964a69e0dd9897c37654e80bb2d9cc7b6e2934/docs/v2-e2e/community-lineage.md) preserves the
historical source and execution scope. The extraction changes ownership only;
runtime dependencies and verification contracts remain unchanged.
