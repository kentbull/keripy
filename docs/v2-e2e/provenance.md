# Native lifecycle provenance and design lineage

This ledger distinguishes source lineage, local design, recorded Git authorship,
and implementation/review work. A Git author is not automatically the inventor
or the party responsible for later adaptations. Unknown origins remain explicit.
Coverage is in progress; this document does not yet account for the full branch.

## INFRA-01: copied Linux test source

Targets: `scripts/v2-e2e/Dockerfile`, `scripts/v2-e2e/check.sh`, and
`scripts/v2-e2e/legacy-peers/check.sh` (module-level build/run instructions).

- Origin: these files entered this branch in
  [`44b336798747f306886ac87b82565d5eaac21a4d`](https://github.com/kentbull/keripy/commit/44b336798747f306886ac87b82565d5eaac21a4d),
  recorded Git author Kent Bull. That metadata alone does not establish the
  original idea's author. The pinned base image/dependency choices are retained.
- Classification: local operational adaptation, implemented by Codex for Kent's
  explicit Docker/LMDB isolation requirement; not a KERI/ACDC protocol rule.
- Change: copy source, tests, scripts, static resources, and test configuration
  into Linux image storage and install the actual KERIpy wheel. Remove source
  bind mounts from both runners; released-peer images already contain their
  service program. `V2_TEST_IMAGE` selects an isolated image tag for scoped runs.
- Rationale: source access and LMDB state must not require macOS-host bind mounts
  during qualification. Installed-wheel testing also exposes packaging failures
  that a source-only `PYTHONPATH` can hide.
- Validation: five distinct-index tests and both real released-peer cases pass
  with the copied-source runner. See `refactor-status.md` for exact commands.
- Boundary: named test volumes remain local operational state. This change does
  not claim to fix macOS resource accounting or establish cross-version database
  compatibility. Dockerfiles retain existing licensing/source attribution.

## Documentation ownership

`refactor-status.md` and this ledger are locally authored by Codex under Kent's
documentation/provenance requirement. Reported execution results come from the
specified commands. Retrospective origin research must cite evidence rather
than silently attributing local implementation decisions to specification authors.

## R7: exact blinded-opening digest verification

Targets: `acdc.regeventing.vetBlind`; all constants, the `opening` helper, and
test functions in `tests/acdc/test_blid_digest_profile.py`.

- Inherited implementation: Daniel Hardman's
  `1a2581ba667054e4486388ec99fc0c46bbc5c3c1`, originally
  `acdc.registring.vetBlind`; renamed in
  `11c5c51294bc83eff411701ca03727f37c3081e2`. These are recorded Git authorships.
- Contract: pinned ACDC
  [BLID calculation](https://github.com/trustoverip/kswg-acdc-specification/blob/f0bd097de318fbbe2d069a2b46cecd42550762e3/spec/spec-body.md#calculating-the-said-of-the-serialized-blinded-attribute-block)
  commits to ordered CESR primitive serializations with the digest slot dummied.
  Supported digest codes must serialize to 44 characters. State and bound-number
  primitives retain their permitted original encodings.
- Local correction: Codex implementation and independent Codex review for Kent.
  The anchored `Diger` chooses the digest algorithm; its canonical encoding and
  equality with opening `d` are checked. Verification hashes original primitives,
  replacing only `d`, rather than reconstructing normalized semantic values.
- Review changed the implementation: the initial algorithm-selection repair
  still normalized `NumDex.Long` and `StrB64_L1`. Independent counterexamples
  showed rejection of valid encodings and acceptance of invalid `verify=False`
  objects. The 12 failing exact-encoding cases pass after exact-byte verification.
- Tests are locally designed; SHA-256 also uses Python hashlib as an independent
  oracle. Coverage includes five 256-bit codes, both clans, altered fields,
  invalid/long/trailing digests, placeholder fields, and public empty nonce.
  The 59-case profile and 27 existing registry tests pass in the installed Linux
  wheel. This does not establish R6 conflict policy or complete qualification.

## R5-A: service-owned KRAM pruning

Targets: `app.registrar.serving.Context.__init__` and
`tests/app/test_native_service_pruning.py` (test and nested context factory).

- Existing service composition entered in `66cbec1b088175246a25aa599b479cacf2031f00`,
  recorded Git author Kent Bull, drawing on keri-foundation/kf-registrar
  `bf14eac4d644275a13cbd3c5900cc2e4dd7c11d1` (Apache-2.0).
- Reused `core.kraming.Pruner`: Keanu's
  `a8bafd15afebaeffe1c566408762ea3a760ad33d` and
  `afb81182cf41783bae05930e91d138390750ad83`, verified by Git blame.
  Existing cache deadlines, authentication, and pruning rules remain authoritative.
- Local Codex composition gives each evidence service one scheduled Pruner for
  its intake Kramer. Observer inherits this concrete runtime owner. This repairs
  absent lifecycle wiring; it does not define a new KRAM timing constraint.
- New tests authenticate real signed service queries, cancel, reopen persistent
  Linux stores, and expire caches by advancing receiver time. They verify retained
  KEL evidence and rejection of the now-expired original query. No cache row is
  fabricated. Both registrar and observer cases pass.
- This unit covers service ownership only. Group/CLI/Dolly composition is tracked
  separately before closing the whole R5 gate.

## R2/R3-A: shared native semantic context and restart lookup

Targets: `acdc.ipexing.NativeVerification` and its methods; native/app
`IpexHandler.__init__` and `loadHandlers`; native `_evaluateLeaf`,
`_verifyNodeSchemas`, `_verifyIssuerAuthNode`, `_boundEdgeValidity`,
`verifyEvidence`; `app.credentialing.Wallet.__init__`, `_verification`,
`recordAdmission`; `cli.common.native_exchange.Peer.__init__`; new/changed tests
in `test_native_wallet.py` and `test_ipex_verification_context.py`.

- Source lineage: schema validation `4e1d2140f116d95d12158a5029a87662020d3e19`,
  leaf evaluation `f09d49e91e2a308f43993b499cdfeb1f6056e0f7`, retained verification
  `825229806db825fdce180cb2a11ec31ed66aee03`; wallet reference bookkeeping
  `d30395c1acbf609d9099f9ce34288d1d4c89233f`, Peer composition
  `93fef663f53ee49187747caf207bc9173c9b6fc1`, and version dispatcher
  `a17fdc0b4601d8527224d62e0b4212e48e12f973` are prior branch contributions.
- Local Codex design: one concrete frozen context carries actual Habery/Regery,
  explicit graph policy, and independent schema store into intake and fresh
  consent. It carries no acceptance assertion; concrete core verification still
  runs. Existing consent is inspectable history, not fresh policy acceptance.
- Independent sections supply schema evidence only. Validation uses the retained
  disclosed node, so cached fuller content cannot widen a presentation.
- Restart correction follows existing `db.basing.statedict` membership/index
  read-through. Its `get` sees warmed entries only. Three native lookups now load
  persisted verified foreign key state without requiring a new replay. Dolly's
  schema tests exposed this defect and pass across full reopen without replay.
- Tests and delta are agent-authored, independently reviewed. AVG/WAVG acceptance,
  rejection with absent/changed policy, exact owner/type guards, independent own
  and edge schema arrival, and retained-view checks cover the shared boundary.
  Group and Dolly parser wiring have separate review units.

## R1/R3-B/R4/R5-B: Dolly intake and evidence composition

Targets: Dolly `Context.__init__`, `_parser`, `ingest`, `_nativeCredential`,
`_nativeCurrentStanding`, `process`, `close`, `setup`; `IntakeEnd` methods;
new/changed cases in `tests/app/test_dolly.py`. These files are temporary staging
locations pending their move into the standalone Dolly repository.

- Dolly baseline: `a17fdc0b4601d8527224d62e0b4212e48e12f973`, recorded Git author
  Kent Bull, with Sally composition precedent retained in the module header.
  Existing `Serdery` provides protocol-aware decoding; existing section ownership
  derives from `825229806db825fdce180cb2a11ec31ed66aee03`.
- Local Codex design: validate empty grants, then classify them non-reportable
  without hooks; isolate current-standing policy; decode original HTTP bytes
  without a KERI-only Serder assumption; share one section store between parser
  and verifier; schedule the evidence owner and its pruner as one child.
- Six real own/edge schema tests exercise arrival before/after grant and full
  reopen, without schema preloading or KEL replay. Fuller section caching cannot
  change retained disclosure or hooks. Raw and header-form JSON evidence tests,
  malformed framing, legacy delivery, and pruner cancellation also pass.
- All 16 Dolly module tests pass. R8 policy separation and repository extraction
  remain separate work; these tests do not establish raw TCP support.

## R3-C/R5-C: group section intake and runtime ownership

Targets: `NativeGroup.__init__`, `ExchangeDoer.run` composition, group fixture
and schema cases in `test_native_groups.py`, and `test_native_group_pruning.py`.
NativeGroup and fixtures derive from `93fef663f53ee49187747caf207bc9173c9b6fc1`;
Pruner lineage is recorded under R5-A. New composition/tests are Codex-authored.

Both direct and mailbox parsers receive the verifier's Sectioner. The command
schedules its evidence owner; a group sharing that Kramer adds no pruner. A
standalone group creates and schedules exactly one Pruner. Four real threshold
approval cases cover independent schema arrival and unchanged partial views;
two authenticated-cache cases cover expiry, cancellation, resumed scheduling,
and retained EXNs. All 12 group tests pass in the installed Linux wheel.

## R8: historical evidence inspection versus current reporting

Targets: Dolly `_nativeDisclosure`, `_nativeCredential`, `inspectHistorical`,
`_historicalSources`, and every helper/test in `test_dolly_historical.py`.
The disclosure boundary extracts existing logic at `9cf8dcd6`; the historical
test adapts `test_bound_state_profile.test_production_graph_bound_authority_uses_real_anchored_history`
from `825229806db825fdce180cb2a11ec31ed66aee03`.

Codex locally designed an explicit read-only inspection purpose. It reuses core
verification and exact retained projections, returning authenticated bound TEL/KEL
references and `currentStanding=not-evaluated`. It emits no hook, submission,
timestamp, or freshness claim. Current reporting still applies its all-node
standing and observer policy. This is application policy separation, not new
KRAM or historical snapshot semantics. Five focused tests cover a real bound
authority graph after revocation, current-reporting refusal, historical inspection
across reopen, invalid proof refusal, retained privacy, and actual hook silence.

## R6-A: authenticated local conflict evidence

Targets: `RegBaser.reopen`/`recordConflict`, `regeventing.vet` documentation,
`_RegEventer.processEvent`, `_validateEvent`, `_processConflict`,
`_processOccupied`, `_commit`, escrow processing and arbitration documentation;
all helpers/cases in `test_registry_conflict_policy.py` and the occupied-slot
assertion in `test_observing.py`.

- Inherited engine: Keanu's `c8f8797841a2dafc463a610694a634b0b795eab6`,
  `60acc017f36bdb74ea6981a4db583b43f7e7352e`, and
  `8332b8dc4271354af035f416226e34d4fa820f56`; later local escrow cleanup
  `825229806db825fdce180cb2a11ec31ed66aee03` is now replaced. RegBaser scaffold
  originates with Evan Asakawa's `0052b7f362692e0b14dd78729c120c644b4bc100`.
  Atomic acceptance from `64a1a01d7537a3ef4dd8d52e5874160dbc60b093` is unchanged.
- Local Codex policy/implementation: preserve the first authenticated accepted
  candidate. Jointly queued candidates retain existing verified-anchor ordering;
  neither ordering claims a globally consistent winner. Strict batch verification
  refuses a supplied proven-conflicting bundle. Durable intake keeps its accepted
  history and reports authenticated competitors separately.
- An occupied slot alone proves no duplicity. Missing anchors remain pending;
  an independently verified competing anchor produces `DuplicitousRegistryError`.
  The additive `conflicts.` table retains one exact competing body per accepted
  slot, with accepted and competing KEL references in existing anchor storage.
  This is bounded local evidence, not exhaustive archiving or fork reconciliation.
- Nine real independent-KEL cases cover opposite arrivals, both queue types,
  delayed anchors, forged signatures/wrong locators, repeats, and reopen. All fail
  with the pre-repair engine substituted. The new cases and existing registry/
  observer modules pass 78 tests. An old assertion now correctly treats an
  unanchored disagreement as pending rather than proven.

## R6-B: service conflict outcomes and observer availability

Targets: registrar `Context.ingest`, observer `Context.observe`, and
`test_occupied_slot_rival_is_pending_until_signed_anchor_arrives` /
`test_old_unanchored_rival_does_not_monopolize_observer_freshness`.
Existing service lineage is `66cbec1b088175246a25aa599b479cacf2031f00`; module
headers retain the upstream registrar/observer adaptation references.

The locally designed integration reports actual pending rivals even at occupied
slots, and never clones their TEL bodies as accepted. An old unanchored rival
cannot block a later clean observer pull at an already accepted ordinal. The
current supplied batch and genuine missing-prefix dependencies still block
freshness. Freshness describes the selected accepted chain and observation; it
does not certify absence of competing issuer evidence. Both regressions fail
with the previous service methods, and all 24 conflict/service cases pass.

## H: optional custody and ordinary native CLI operations

Targets: moved `CustodyInfo`, `_Custody`, `EncryptedCustody` and all eight secret
methods into `app.registry_custody.RegistryCustody`; its constructor and guard;
`Wallet.__init__`/`recordIssued`; native CLI `options`, `opened`, `standing`,
`NativeAuthor.update`/`run`, read/export/import composition; native IPEX `run`
and `registryOrigin`; inception/grant arguments; wallet/custody/CLI regressions.

- Move lineage: `d30395c1acbf609d9099f9ce34288d1d4c89233f`, with extraction
  baseline `ea3d82811c6737f410f9418250e66fe22637b5ca`. Existing encrypted payload,
  table key, environment, Keeper cryptography, and local binding checks remain.
  The new concrete boundary, explicit proof/history handling, and no-regeneration
  guard are local Codex designs under Kent's approved capability separation.
- Wallet defaults to no custody. Fresh blinded issuance needs a supplied opening
  checked by core `vet`; exact retained issuance retries make no current-standing
  claim and need no salt. Missing custody cannot regenerate after accepted `bup`
  history; explicit provisioning after public-only history remains supported.
- CLI `--with-custody` explicitly provisions at registry inception. Public flows
  create no secret. Ordinary opening passes no passcode to an unencrypted Keeper,
  avoiding implicit encryption migration; encrypted identities still authenticate.
  `--refresh --opening` supplies event-specific CESR evidence; `--refresh --derive`
  explicitly uses a provisioned derivation owner. Both paths retain core proof
  checks. `--v2` is the preferred selector; `--native` remains its alias.
- Independent review caught a remaining historical retry derivation in CLI.
  Removing it and suppressing blinded current-standing inference makes retries
  survive lost custody, proved by a subprocess regression. Inventory similarly
  reports unknown blinded standing without opening private records.
- Keeper `Manager.updateAeid` migrates Keeper material only. Custody migration is
  deliberately unsupported: old-AEID derivation fails, while retained presentation
  continues. Recovery remains explicit plaintext mode-0600 re-import, not encrypted
  transfer, a signed delegation, or automatic key rotation support.
- The large move preserves one existing storage contract and updates all direct
  CLI callers together. Review the moved method bodies separately from their
  expanded documentation, then the optional composition and history checks.
  Twenty-six wallet/custody tests, seventeen CLI/custody tests, seven final author
  retry tests, and the selector test pass; scenario-level qualification remains.
