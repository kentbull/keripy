# Native lifecycle provenance and design lineage

This ledger distinguishes source lineage, local design, recorded Git authorship,
and implementation/review work. A Git author is not automatically the inventor
or the party responsible for later adaptations. Unknown origins remain explicit.
The branch-wide [lineage inventory](lineage-inventory.md) and
[machine-readable unit ledger](lineage-symbols.json) enumerate inherited/local
parts against the verified upstream start, earlier reviewed baseline, committed
state, and active working tree. Their explicit review states distinguish coverage
from still-active scenario/final-artifact reconciliation; the grouped notes below
explain decisions without duplicating every qualified symbol.

## Core-only installed-package test tooling

`scripts/v2-e2e/Dockerfile`, `check.sh`, and `requirements.lock` remain here
because they build and test KERIpy independently. Their copied-source and named
Linux-volume pattern entered in
[`44b336798747f306886ac87b82565d5eaac21a4d`](https://github.com/kentbull/keripy/commit/44b336798747f306886ac87b82565d5eaac21a4d).
Git records Kent Bull; Codex implemented the local operational adaptation for
his Docker/LMDB isolation requirement. This is tooling provenance, not a protocol
rule or a claim to fix macOS resource accounting. Peer/composition runners and
their execution history are owned by the independent experiment repository.

## Documentation ownership

This ledger and the historical refactor report are locally authored by Codex under Kent's
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
`IpexHandler.__init__` and `loadHandlers`; native `_evaluateLeafEdge`,
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

Targets: moved `CustodyInfo`, `_Custody`, `EncryptedCustody` and all eight
private-derivation methods into `app.registry_custody.RegistryCustody`; its
constructor and accepted-history guard;
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
  continues. Recovery remains explicit plaintext mode-0600 re-import. Import
  checks the operator-selected registry/controller/discloser against accepted
  evidence and then encrypts the record locally; this is not an encrypted transfer
  protocol, a signed delegation, prevention of plaintext copying, or automatic
  key-rotation support.
- The large move preserves one existing storage contract and updates all direct
  CLI callers together. Review the moved method bodies separately from their
  expanded documentation, then the optional composition and history checks.
  Twenty-six wallet/custody tests, seventeen CLI/custody tests, seven final author
  retry tests, and the selector test pass; scenario-level qualification remains.

### KRAM sender state after process restart

Dolly's installed-console restart test exposed four `Kramer.kramit` lookups
using `statedict.get`, which only checks the in-memory Kever cache. Replace them
with the existing Baser membership/index read-through idiom so already verified
persistent KEL state can authenticate a new message after restart. This is a
local integration repair using upstream Baser behavior, not a new KRAM timing
rule. Unknown senders still require authenticated key-state evidence.

Four cold-cache regressions cover query/exchange and single/multi-key delivery;
all four fail with the previous lookup restored. The complete KRAM file plus
native sender transport tests pass (60 cases). The existing monotonicity test
now deliberately removes persistent sender state as well as RAM state, keeping
its original assertion about rejection order without relying on the cache bug.

### Native direct TCP sender

`ExchangeDoer.request` now accepts `tcp://host:port` for exact signed CESR
transmission. Its HIO ownership and send-buffer boundary follow existing
`keri.app.agenting.TCPMessenger.receiptDo`; URL constraints, timeout, cancellation
cleanup, and the transport-only result are local CLI composition decisions.
Observer requests still require HTTP response evidence. Six real-socket and
invalid-destination tests pass, including multi-buffer byte preservation and an
unavailable peer deadline. TCP send completion never claims receiver acceptance.

### Finite StreamPoster TCP delivery

Review of the new legacy negotiation default delivery found an inherited
`streamMessengerFrom` TCP branch that discarded its `msg` argument and returned
a perpetual queue service. The local repair gives `TCPStreamMessenger` a finite
single-message contract matching existing `HTTPStreamMessenger`; the separate
`TCPMessenger` remains a persistent queue/receipt service. KERIpy/HIO client
ownership is reused, and no authenticated acceptance follows from buffer drain.

Eleven focused tests pass: real controller and mailbox endpoint selection in
both genus versions, empty/nonempty factory payloads, cancellation-owned socket
closure, preservation of the persistent messenger, and existing HTTPS preference.
The API change is limited to the stream class's sole in-tree factory caller.


## CLI adapters: explicit evidence and versioned negotiation

Targets: `cli.common.public_evidence` and its command/parser modules;
`cli.common.legacy_negotiation.Negotiation`; `ipex.grant.GrantDoer` additions;
`cli.common.cesr_sending.send`; corresponding installed CLI/transport tests.
Every changed qualified function, parser/module snippet, and test helper has a
stable entry in the unit inventory; these notes state the shared design boundary.

Public KEL import/export reuses existing Parser/Kevery/Revery acceptance and exact
endpoint-reference tables. The implementation never injects accepted database
rows. Native publication/query uses existing signed registrar requests; query
results must independently verify to the advertised fresh head. Explicit opening
export and state-preserving advance reuse RegistryCustody plus common vetBlind/
vetBound checks. Ordinary evidence commands preserve existing Keeper encryption
mode and compose no private derivation capability. New parser aliases and
exclusive output files expose existing concrete owners rather than new protocol
engines. These are locally agent-designed operator adapters under Kent's explicit
CLI completion request; no exact external code donor is asserted.

Legacy negotiation adapts existing `vc.protocoling` constructors, saved credential
proofs, accepted thread messages, and StreamPoster delivery. Its predecessor
apply/offer/agree commands were nonce stubs. The new v1 default does not translate
native registry semantics into legacy TEL or disable native authentication.
Grant's acceptedAgreement checks the actual signed recipient agreement, issuer
Offer/credential, and optional Apply parties/schema; directStream uses existing
credentialing artifact/source replay contracts. These are bounded local CLI
compositions, not claims that the original protocol constructors or ideas were
invented here. The introducing adapter commits and inherited-source links are
recorded per symbol.

The shared direct sender was extracted from the native adapter after both
versions needed the same finite HTTP/TCP contract. HTTP retains path/query and
propagates refusal; TCP proves only local buffer drain. The exact-byte/socket,
subprocess negotiation, public Keeper, and independently verified service tests
exercise those boundaries. Historical individual test counts elsewhere in this
ledger are scoped executions, not a final combined qualification claim.

### Legacy proof framing and explicit direct admission

The narrow serializer correction in
[`e49973a7265859684eadb1ef6b50811b074ea324`](https://github.com/kentbull/keripy/commit/e49973a7265859684eadb1ef6b50811b074ea324)
adapts the inherited `app.signing.serialize` helper: attachment genus follows the
credential's genus/protocol version while the exact body and caller-supplied
source triple remain unchanged. A v1 body previously received a v2 footer under
current library defaults, so the actual parser did not recover its source proof.
This is a local framing repair, with no new verification or acceptance rule.
The new real-Parser regression checks both versions and nonzero source ordinal;
the owner's copied installed-wheel signing/direct-admission run passed four
tests. The old serializer failed its v1 case and passed v2.

Direct legacy admission in
[`2b800136130d7f7c4cd8d4b795d0c6312e918cb2`](https://github.com/kentbull/keripy/commit/2b800136130d7f7c4cd8d4b795d0c6312e918cb2)
composes the existing `AdmitDoer` processing order, legacy Verifier, ordinary
escrows, and `protocoling.ipexAdmitExn`. Explicit input/output/endpoint options
select this bounded individual adapter; the existing mailbox/group path remains
available. It verifies the authentic addressed Grant and its anchor/TEL/ACDC
dependencies before authoring a response. Its real missing-schema regression
requires an authentic retained Grant and verifier escrow, no saved credential,
timeout with no output, then successful admission after schema import. The
owner's focused installed-wheel run passed one test. This is locally generated
CLI composition using existing core contracts, not a separate credential verifier.

The later Grant lifecycle correction in
[`f55d60770658d28d432dfb9cb044a0c53ae24371`](https://github.com/kentbull/keripy/commit/f55d60770658d28d432dfb9cb044a0c53ae24371)
follows the inherited HIO `DoDoer.remove`/`exit(deeds=…)` contract. Selective
transport-child removal must preserve the still-running owner's stores; only
full owner exit closes Noter, Regery and Habery. The real HTTP CLI regression
captures the exact exported Grant bytes, then requires authenticated local
completion and ordinary admission. The owner reports one passing installed-wheel
test. This is a local lifecycle repair, not an HTTP acknowledgment granting
credential acceptance.

### Established v1 identity and evidence-source composition

Witness startup in
[`f42647d194545a20d97a4386d3fcd868f72a9479`](https://github.com/kentbull/keripy/commit/f42647d194545a20d97a4386d3fcd868f72a9479)
selects framing from the persisted alias rather than a generic library default.
The local repair reuses existing `setupWitness`; its installed-process regression
submits genuine v1 and v2 inceptions and core-verifies the resulting witness
signatures. The test moved from the in-progress evidence-service test file into
`tests/app/test_witness_protocol_cli.py`; that move preserves its fixture and
assertions rather than supplying a second independent test implementation.

The `cli.common.legacy_evidence` service and `vc registry serve` command in
[`c380866b16066a0cd00f562c4026e0d3f5a09a05`](https://github.com/kentbull/keripy/commit/c380866b16066a0cd00f562c4026e0d3f5a09a05)
have completed their scoped source/documentation review. They compose
existing attachment verification and conventional `Tevery.processQuery` cues,
with an explicit reader allowlist and one operator-configured reply endpoint.
The current implementation bounds input frames, queued replies, reply size,
and delivery retries. It serves accepted public evidence, supplies no issuer
authoring shortcut, and requires restart after external authoring to refresh its
public state. These are local operational constraints rather than normative v1
wire rules. An entire refused HTTP body queues no earlier-frame reply, and the
service drains each cue batch before serializing so an oversized response cannot
leak a later cue into another request. The final v1 replay path uses the existing
Reger cloner with explicit v1 attachment genus. The real Parser regression
requires exact vcp/iss source ordinals and KEL digests as well as v1 bodies.
The owner's two socket/persisted-reader tests pass; final clean qualification
remains separate. Previously reported AuthError/HTTP-415 documentation gaps are
closed in the committed contracts.

The incept/create/revoke changes in
[`b0d30d05c0c1f4df330cd63f477820d93441f641`](https://github.com/kentbull/keripy/commit/b0d30d05c0c1f4df330cd63f477820d93441f641)
select local and receipt/mailbox parsing from the established alias and preserve
the selected registry's anchor version and serialization kind. Constructor and
generator documentation now states inputs, yielding/completion, errors, and
ownership. The real CLI regression issues and revokes under legacy v1 and explicit
native v2, then inspects exactly four KEL events for the selected version and
three actual registry seals. The owner reports two passing cases; this fixture
uses no witnesses, so it does not replace the separate witnessed Bash execution.

Schema import in
[`96c540938faebf99f34008daf05263f1e1021761`](https://github.com/kentbull/keripy/commit/96c540938faebf99f34008daf05263f1e1021761)
accepts the configured environment passcode for an encrypted Keeper while
preserving unencrypted mode. Its two installed CLI cases reopen each store,
require the exact imported schema and unchanged AEID, and refuse a wrong encrypted
passcode without import or migration. These are locally generated adaptations
and regressions around existing CLI/Keeper owners; the owner's two passing cases
are scoped evidence. Clean cross-repository qualification remains separate.

## Whole-block disclosure decision

`IpexHandler._verifyDisclosurePlan` inherits the local empty-field/empty-path
interpretation and canonical Compactor path handling. The narrow correction in
`d2c9fd79` rejects selectively hidden aggregate members under the empty-string
request because aggregate positions structurally identify blocks. It deliberately
does not classify arbitrary digest-valued attribute strings as hidden blocks.
The exact scalar and compacted-block interpretations can produce identical valid
received bytes. Existing schema validation can require an object; explicit leaf
paths can require its contents. The [profile](profile.md#whole-block-disclosure-requests)
records this approved provisional contract against pinned ACDC's distinction
between block-level expansion and full disclosure, and its non-normative IPEX
outline. Three focused regressions and the existing IPEX module pass 92 cases.

## S5: authenticated opening with an unavailable TEL event

Targets: `IpexHandler._vetRegistry` and every class/helper/test in
`tests/acdc/test_ipex_registry_dependency.py`; runtime correction
[`7e648d3ac1f9990eaf3685f10845593c306e20fa`](https://github.com/kentbull/keripy/commit/7e648d3ac1f9990eaf3685f10845593c306e20fa).

The selected-discloser scenario exposed a verifier holding accepted event 1 while
receiving a valid target opening for unavailable event 2. Its permanent refusal
prevented ordinary EXN escrow and observer acquisition. The local Codex repair
classifies a self-verified unmatched target opening as a missing dependency,
without inventing its ordinal, publication time, standing, or eventual acceptance.
It preserves exact historical-source selection and permanent refusal for malformed,
wrong-target, duplicate-known, and contradictory bound proofs regardless of order.
The fixture adapts existing real anchored-registry patterns from `test_ipexing`;
it does not copy a separate verifier or inject accepted rows.

Both bound/unbound regressions failed at the old missing-escrow boundary, then
passed with ordinary KEL/TEL acquisition and no Grant replay. An opening never
committed by an acquired TEL remains unresolved. The final scoped IPEX/bound/
digest/native registry/form/graph execution passed 336 cases. Parent source
review confirmed this dependency contract; it does not make the verifier's
unknown event into authenticated current state. Subsequent helper documentation
was checked as executable-AST-equivalent and adds no runtime result.

## Experiment ownership

Cross-repository recipes, external acceptance scenarios and dated evidence are
owned by the independent `keri-v2` experiment repository. They are not required
to run this component. [Pre-extraction record](https://github.com/kentbull/keripy/blob/81964a69e0dd9897c37654e80bb2d9cc7b6e2934/docs/v2-e2e/provenance.md) preserves the
historical source and execution scope. The extraction changes ownership only;
runtime dependencies and verification contracts remain unchanged.
