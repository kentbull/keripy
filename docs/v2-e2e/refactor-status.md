# Refactor qualification status

The `e45f57fbf524ab0a9739baa4786dcbc5e6632ba2` branch is the R&D
foundation, not yet the qualified TypeScript behavioral reference. The current
work retains its useful protocol machinery while closing the adversarial review,
optional-custody, standalone-Dolly, and operator-workflow gates.

## Baseline

- Execution began 2026-10-20; continued 2026-10-21 (America/Denver).
- Upstream `WebOfTrust/keripy:main`, checked remotely at execution start:
  `c7e74adc3129ba36302db32e58056560b0927424`.
- Integration branch `kentbull/keripy:v2-e2e`, clean at execution start:
  `e45f57fbf524ab0a9739baa4786dcbc5e6632ba2`; remote matched.
- `kentbull/dolly` was empty when inspected and cloned. Standalone source,
  schemas, application tests, and released-peer tooling are published on master
  at `b0fc03699fd1762779ef20a0470e4f78cc2744c7`. KERIpy-side deletion
  was committed separately in `157c23cb`; no compatibility package remains.
- Source/state qualification uses copied Linux source and Docker-managed LMDB
  volumes. No host bind mount is required by either test runner.

## Completed evidence

| Review unit | Validation | Result |
|---|---|---|
| Linux-owned test source and installed KERIpy wheel | `V2_TEST_IMAGE=keripy-v2-refactor:runner V2_TEST_VOLUME=keripy-v2-refactor-runner scripts/v2-e2e/check.sh tests/core/test_threshold_distinct_indices.py` | 5 passed |
| Released-peer runner without host mounts | `V2_MATRIX_IMAGE=keripy-v2-refactor:runner LEGACY_SKIP_BUILD=1 scripts/v2-e2e/legacy-peers/check.sh` | 2 passed, actual 1.2.14/1.3.6 peers |
| R7 declared digest and exact opening bytes | `V2_TEST_IMAGE=keripy-v2-refactor:blid-exact V2_TEST_VOLUME=keripy-v2-refactor-blid-exact scripts/v2-e2e/check.sh tests/acdc/test_blid_digest_profile.py tests/acdc/test_regeventing.py` | 86 passed; independent review exposed and corrected encoding normalization |
| R5-A registrar/observer pruner ownership | `V2_TEST_IMAGE=keripy-v2-refactor:pruner V2_TEST_VOLUME=keripy-v2-refactor-pruner scripts/v2-e2e/check.sh tests/app/test_native_service_pruning.py` | 2 passed: authenticated cache, expiry, cancellation, reopen, stale-query refusal |
| R2/R3-A shared configured admission and schema context | `V2_TEST_IMAGE=keripy-v2-refactor:context-final V2_TEST_VOLUME=keripy-v2-refactor-context-final scripts/v2-e2e/check.sh tests/app/test_native_wallet.py tests/app/test_native_ipex_cli.py tests/acdc/test_ipexing.py tests/acdc/test_ipex_verification_context.py` | 119 passed; independent review accepted concrete context and read-through lookup |
| R1/R3-B/R4/R5-B Dolly composition | `V2_TEST_IMAGE=keripy-v2-refactor:dolly-sections V2_TEST_VOLUME=keripy-v2-refactor-dolly-sections scripts/v2-e2e/check.sh tests/app/test_dolly.py` | 16 passed, including six independent own/edge schema arrival/reopen cases, retained projection, actual hooks, pruner cancellation |
| R3-C/R5-C group composition | `V2_TEST_IMAGE=keripy-v2-refactor:group-sections V2_TEST_VOLUME=keripy-v2-refactor-group-sections scripts/v2-e2e/check.sh tests/app/test_native_groups.py tests/app/test_native_group_pruning.py` | 12 passed: direct/mailbox sections, threshold approval, single pruner ownership, expiry/cancellation/reschedule |
| R8 historical inspection/current reporting | `V2_TEST_IMAGE=keripy-v2-refactor:dolly-historical V2_TEST_VOLUME=keripy-v2-refactor-dolly-historical scripts/v2-e2e/check.sh tests/app/test_dolly_historical.py tests/app/test_dolly.py::test_native_partial_full_grants_observer_acquisition_and_real_webhooks tests/app/test_dolly.py::test_empty_grant_is_terminal_and_later_grants_report_after_reopen` | 5 passed: anchored bound history, revocation, reopen, invalid proof, hook silence |
| R6-A authenticated conflict policy | `V2_TEST_IMAGE=keripy-v2-refactor:conflict V2_TEST_VOLUME=keripy-v2-refactor-conflict scripts/v2-e2e/check.sh tests/acdc/test_registry_conflict_policy.py tests/acdc/test_registraring.py tests/acdc/test_regeventing.py tests/acdc/test_observing.py` | 78 passed; all nine new cases fail under the old event engine |
| R6-B service outcomes and availability | `V2_TEST_IMAGE=keripy-v2-refactor:conflict-services V2_TEST_VOLUME=keripy-v2-refactor-conflict-services scripts/v2-e2e/check.sh tests/acdc/test_registry_conflict_policy.py tests/app/test_native_services.py` | 24 passed; independent review accepted core/service contract |
| Optional custody storage and held presentation | `V2_TEST_IMAGE=keripy-v2-refactor:custody V2_TEST_VOLUME=keripy-v2-refactor-custody scripts/v2-e2e/check.sh tests/app/test_native_wallet.py tests/app/test_registry_custody.py` | 26 passed; absent/unencrypted/corrupt/old-AEID custody does not block retained presentation |
| Optional CLI and supplied opening | `V2_TEST_IMAGE=keripy-v2-refactor:optional-cli-final V2_TEST_VOLUME=keripy-v2-refactor-optional-cli-final scripts/v2-e2e/check.sh tests/app/test_native_cli.py tests/app/test_native_ipex_cli.py tests/app/test_registry_custody.py` | 17 passed; actual supplied-opening onward grant/admit without salt import |
| Final history-retry correction | `V2_TEST_IMAGE=keripy-v2-refactor:optional-retry V2_TEST_VOLUME=keripy-v2-refactor-optional-retry scripts/v2-e2e/check.sh tests/app/test_native_cli.py` | 7 passed, including exact issuance retry after test custody-row loss |
| Explicit version selector | `V2_TEST_IMAGE=keripy-v2-refactor:version-alias V2_TEST_VOLUME=keripy-v2-refactor-version-alias scripts/v2-e2e/check.sh tests/app/test_native_cli.py::test_native_option_is_explicit_and_legacy_remains_default` | 1 passed; v1 default, --v2 and --native aliases |

These targeted checks qualify their named units, not the complete refactor.
Paths in the table are the historical commands at execution time; Dolly tests
and the released-peer runner now belong to the standalone Dolly repository.
The historic 799-test result is not new evidence for the current changes.

## Integration checkpoint (2026-10-21)

| Review unit | Actual focused result |
|---|---|
| Restart-safe KRAM lookup | Four cold-cache counterexamples fail with the earlier lookup; 60 combined tests passed after read-through correction. |
| One-shot StreamPoster TCP | 11 focused delivery tests passed; persistent TCPMessenger behavior remains separate. |
| Shared direct sender and v1 negotiation | 24 protocol/transport/selector tests passed; final HTTP query/refusal plus installed apply/offer/agree/grant run passed 9. |
| Public evidence/opening commands | 3 installed-CLI tests passed, including actual signed registrar/observer services and foreign admitted-credential derivation. |
| Whole-block disclosure boundary | 92 IPEX tests passed, including aggregate withholding, opaque scalar ambiguity, and existing schema structural enforcement. |
| Standalone Dolly | 25 application tests passed; both encrypted and unencrypted installed-console HTTP/TCP/restart cases passed. Two released-peer cases are skipped in the default suite and passed in the separate actual 1.2.14/1.3.6 matrix. |
| Moved witnessed lifecycle | Dolly integration passed with three witnesses/quorum two, independent services, restart, revocation, and exact retained disclosures. |
| S1–S4 Bash stories | All four passed in one installed working-source build, with explicit three-leaf full-disclosure assertions. Clean published-artifact rerun remains required. |
| S6 separate discloser with custody | TCP run passed in the same six-scenario build: both real hooks, explicit holder consent grants, scoped custody, and later-event derivation. |
| S5 separate discloser with openings | A real stale-known-TEL dependency failure was reproduced and corrected in `7e648d3a`; 336 related profile tests passed. The original Bash counterexample now passes in the same six-scenario build; final clean-artifact rerun remains required. |
| Credential source-proof genus | `e49973a7` corrects v1 credentials carrying a v2 source-proof footer. A real Parser counterexample fails before the fix; four signing/direct-admission tests pass afterward, including v2 preservation. |
| Direct v1 admission | `2b800136` adds explicit individual direct admission through existing credential verification. Installed CLI test passes wrong-recipient and missing-schema refusals, dependency arrival, successful admit, and issuer receipt authentication. |
| Established-version witness | `f42647d1` makes persisted witness protocol select endpoint framing. Real installed v1/v2 HTTP requests both return core-verified receipts; the v1 Bash three-witness bootstrap now passes. |
| Grant lifecycle after direct transport | `f55d6077` distinguishes HIO selective child removal from full owner exit. Actual HTTP CLI regression passes, including subsequent normal admission. |
| Noninteractive schema import | `96c54093`: two installed CLI cases preserve encrypted/plain Keeper AEIDs; wrong encrypted-store authentication refuses before importing. |
| Established-version author commands | `b0d30d05`: actual registry inception, issue and revoke pass for v1 and explicit native v2; all four exported KEL events retain the selected version. |
| V1 Bash operator story | Development run passed three witnesses/quorum two, genuine issuance, negotiated HTTP/TCP grants, two hooks, local admission, genuine revocation and refusal without a third hook. The explicit v1 replay-genus refinement is covered by `c380866b`; the exact clean published pair remains required. |
| Generic v1 evidence source | `c380866b`: signed allowlisted queries, fixed replies, hostile framing/field/factor refusals, bounded queue/cue cleanup, cold-reader reopening and exact v1 replay source coordinates. Two socket tests pass; development Dolly reporting separately passed core source-state acceptance. |
| Integrated core checkpoint | 973 passed, one obsolete mandatory-custody test expectation failed. `486650ad` corrects the public group contract and checks both custody stores stay empty; focused rerun passed. Final integrated run remains required after later CLI work. |

S5 establishes a specific recovery gap: the receiver has accepted registry event
1, and a signed grant supplies a valid opening for event 2. Semantic verification
returns permanent failure before the ordinary EXN dependency escrow retains the
grant, so Dolly cannot acquire the missing observer evidence. The fix retains existing authentication and exact-proof requirements and uses
normal EXN dependency escrow for an unknown self-verified target opening. Such
an opening proves no newer ordinal or acceptance; known contradictions remain
permanent refusals. No KRAM timing rule is added.

## Remaining acceptance

The current implementation is not yet the qualified TypeScript reference.
Rerun all six independent Bash stories against one clean published installed
source pair, repeat the dedicated v1 Bash operator workflow, and run integrated
and clean-published-checkout qualification. Pin the final dependency and record
artifact hashes, public manifests, and actual transcripts.

Dolly extraction and the operator-link update are committed. Complete final
provenance reconciliation for all earlier and new contributions. Documentation-only source
and test batches are checked for executable AST equality; a symbol inventory is
not a substitute for substantive origin/review coverage. Optional custody,
standalone application, CLI, provenance, and human documentation gates close only
when their named evidence is reconciled here. Unknown historical authorship must
remain explicit, never fabricated.
