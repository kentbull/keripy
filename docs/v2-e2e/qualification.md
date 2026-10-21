# Qualification ledger

Run `scripts/v2-e2e/qualify.sh` from a fresh checkout of the exact handoff SHA.
The final handoff reports that command's result for that commit. Python
qualification is the gate for the TypeScript port. Optional bulk/Merkle
profiles (V34) are outside this declared profile; no required gate is waived.

| Capability / phase | Implementation and falsifying evidence |
|---|---|
| V01–V04, P0/P1/C1: versions, codecs, forms, framing and dispatch | `test_native_forms_profile.py`, `test_native_registry_framing.py`, existing core Serder/Parser tests: explicit/implicit maps, act/acg, four codecs, qb64/qb2, fragmented and truncated streams. |
| V05–V06: KEL/issuer/witness authority | `test_observing.py`, `test_threshold_distinct_indices.py`, existing v1/v2 eventing tests: accepted ordinal membership, historical quorum, actual distinct signatures, dependency recovery. |
| V07–V11, C1: schema, selective disclosure, aggregate/independent sections | `test_native_forms_profile.py`, `test_scheming.py`, existing messaging/Compactor/Aggor tests: exact schema/AGID commitments, persistent missing-section requests, explicit ambiguous-view selection and no automatic disclosure merge. |
| V12–V14/V37, C2: graphs and explicit policy | `test_native_graph_profile.py`, `test_bound_state_profile.py`, Dolly two-node HTTP negotiation: specified logical/relationship operators, declared arithmetic policy, real accepted delegation, missing/invalid far evidence. |
| V15–V18, P1/C1: native TEL acceptance | `test_regbasing.py`, `test_registering.py`, `test_regeventing.py`, `test_native_registry_profile.py`, `test_registry_arbitration.py`, `test_observing.py`: atomic accepted body/ordinal/head, mixed histories, conflicting occupied ordinal, restart and real dependency arrival. |
| V19/V29, P3a: custody and inventory | `test_native_wallet.py`: encrypted Keeper, protected explicit provisioning, binary bytes, designated discloser, future derivation, explicit consent, handlerless EXN rejection, immutable per-grant disclosure, bound coordinates after rotation/reopen. |
| V20–V22, C1/C2/P4: binding and historical presentation | `test_registry_binding_forms.py`, `test_bound_state_profile.py`, `test_historical_evidence.py`, Dolly and group presentation-registry tests: hidden/one-way binding, exact event reference, backdated/resealed counterexamples, immutable grant body before holder binding. |
| V23–V26, P2: registrar/observer | `test_native_services.py`, `test_native_e2e.py`: authorized foreign hosting, independent bulk polling, cache-only verifier queries, replay/conflict/stale reporting, cancellation and reopen. |
| V27–V28, P3b: actual IPEX/KRAM | `test_ipexing.py`, `test_native_ipex_cli.py`, Dolly negotiated two-node test: apply/offer/agree/grant/admit/spurn semantics, actual sender/recipient proofs, source evidence and existing KRAM gates. |
| V30–V32, P3/P4/P5: operator lifecycle | `test_native_cli.py`, `test_native_ipex_cli.py`, `test_native_e2e.py`: real subprocesses, receipts, custody, admission, retained and refreshed presentations, independent revocation and no stale acceptance hook. |
| V33/V35, C3: groups/delegation | `test_native_groups.py`, `test_native_delegated_controller.py`, existing grouping/group-persistence tests, graph DI2I vectors: explicit missing approval, real HTTP fanout, six issuer/holder member stores, threshold convergence, presentation registry, consent and revocation. |
| V35–V36, P5: legacy peers and reproducibility | `test_legacy_peer_profiles.py`, `scripts/v2-e2e/legacy-peers/check.sh`, process walkthrough: actual separately installed 1.2.14/1.3.6 peers, same webhook decision, replay and fresh revoked state. See exact source-adapter limit in `legacy-peers.md`. |

Test names above are under `tests/acdc`, `tests/core`, or `tests/app` as appropriate.
The existing atomic-store tests are part of the earlier integration commits.

## Application demonstrations

A/C/D/E: `test_native_e2e.py` starts independent issuer/holder/Dolly stores and
processes, three witness processes with issuer/holder quorum two, registrar,
independent observer and a real HTTP webhook receiver. It covers issuance,
publication and four full KLI-authored, HTTP-delivered IPEX negotiations:
partial issuer-to-holder and holder-to-Dolly sessions, then fuller sessions
along the same path after restart. It verifies all five messages' receiver
acceptance, predecessor/session links, explicit admission, preserved first-stage
views, and two actual webhook requests. Apply/Offer/Agree alone produce no
webhook; Admit produces no duplicate. Independent revocation, no revoked
acceptance webhook and stale observation refusal complete the scenario.

B: both released peer installations generate real legacy credentials and signed
IPEX grants. Current Dolly uses its existing legacy verifier/evidence machinery;
actual fresh signed source reports are necessary before the same webhook
contract is emitted. Exact replay produces no second webhook. A subsequent
real revocation plus fresh report prevents a new acceptance webhook.

F/E2: `test_two_node_chain_declared_presentation_registry_and_full_ipex_over_http`
uses a two-node authority/entitlement graph, a holder-controlled presentation
registry, issuer/holder rotation and complete negotiated IPEX over HTTP. The
final grant retains the pre-binding body/SAID and only discloses the selected
business section. `test_group_issuer_holder_admission_presentation_and_revocation_converge`
uses real group approvals and HTTP fanout with six distinct member stores.

## Deliberate limits

- This is the documented provisional R&D profile, not an unqualified statement
  of conformance to contradictory published text or a production release.
- Bound coordinates and source seals prove the stated KEL/TEL relationships;
  they do not independently establish globally first wall-clock publication.
- Freshness trusts the configured observer/source observation policy. A stale
  observer cannot detect an unseen revocation. Historical issuance is not a
  promise of current standing.
- Advanced graph/presentation-registry construction uses the public Python
  application/protocol APIs in the runnable socket examples. The simple grant
  CLI does not generate arbitrary graph artifacts or negotiate their policy.
- Core-rejected grants without a retained dependency can remain labeled pending
  in Dolly's submission table. They do not pass policy or produce a webhook.
- Webhook retries can duplicate delivery across a crash after remote receipt
  but before local acknowledgement. No distributed exactly-once claim is made.
- Protected group/discloser secret handoff is operator-assisted. Signing
  approval never implies secret distribution or credential admission.
- Wire interoperability is tested separately from LMDB compatibility. No
  cross-version or Python/TypeScript database-opening promise is made.
