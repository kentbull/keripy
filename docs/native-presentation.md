# Native admitted-view presentation

`ipex present --version 2.0` selects one exact accepted native Grant and its
accepted local Admit. Both signatures, reversed parties, prior link and
transaction XID must verify. It reads only that Grant's retained nested
disclosure, including its artifacts and proofs. A fuller same-SAID disclosure
held under another Grant does not supply missing content.

```sh
kli ipex present --name holder --alias holder --version 2.0 \
  --from-grant "$ADMITTED_GRANT" --recipient "$AUDITOR_AID" \
  --disclose a/name/ --deliver --respond-unblind \
  --output presentation.cesr --timeout 120
```

Omit `--disclose` to retain the exact selected body. Repeated `a/...` paths
narrow the held origin with native Compactor; hidden branches cannot be
expanded. Partial disclosure requires the relevant native section commitments.
Artifacts remain as selected. Multiple nodes require explicit native
`--plan JSON` or `--plan @file` with one DAG disclosure plan. The presentation
starts a fresh transaction and never uses the old Grant as its IPEX prior.

By default proofs come from the selected admitted view. If the sender already
knows newer accepted issuer history, explicitly refresh the new presentation:

```sh
kli ipex present --name holder --alias holder --version 2.0 \
  --from-grant "$ADMITTED_GRANT" --recipient "$AUDITOR_AID" \
  --refresh --opening exact-opening.cesr --deliver
# Or authorize ordinary proof derivation with --refresh --derive.
```

`--opening` may repeat; each file contains exactly one complete native CESR
state opening. Native accepted TEL history and `vetBinds` verify these proofs.
`--derive` authorizes only this signer's existing encrypted Keeper registry
root. Ordinary issued/revoked/vacuous proofs are supported. Exact bound proofs
work when supplied; bound derivation requires a later explicit-coordinate
interface. Refresh does not alter the source Grant's retained disclosure.

An individual separate discloser can retain a held-proof presentation, obtain
independent consent from its registry issuer, then resume the same Grant:

```sh
kli ipex present --name discloser --alias discloser --version 2.0 \
  --from-grant "$ADMITTED_GRANT" --recipient "$AUDITOR_AID" \
  --prepare --output prepared.cesr
# In the independent issuer store, sign the exact reported Grant SAID:
kli ipex endorse --name issuer --alias issuer --version 2.0 \
  --said "$PREPARED_GRANT" --grant prepared.cesr \
  --sender "$DISCLOSER_AID" --recipient "$AUDITOR_AID" --output endorsed.cesr
kli ipex present --name discloser --alias discloser --version 2.0 \
  --from-grant "$ADMITTED_GRANT" --recipient "$AUDITOR_AID" \
  --resume "$PREPARED_GRANT" --input endorsed.cesr --respond-unblind --deliver
```

For a group registry issuer, each member uses its own store and the same original
`--grant prepared.cesr`. The first member writes a partial endorsement; subsequent
members add `--contribution member-1.cesr` (repeat for additional members) and write
a new output file. Until the ordinary issuer signing threshold is satisfied,
the result reports `contributed: true, endorsed: false`. Resume only with the
aggregate reporting `endorsed: true`. Contributions preserve the exact prepared
body and nested evidence and must use the same issuer establishment event.

Complete public KEL/TEL/schema acquisition and explicit encrypted root
provisioning before preparation. Preparation exports exactly one public Grant
frame, approves no Unblind operation and sends nothing. Its original native
fallback lifetime is **10 seconds**; endorsement, resume and live verification
must complete within that window. `--timeout` cannot extend it. This bounded path does not
provide time for leisurely human or multi-person approval.

Use the same recipient, message, disclosure paths and plan at prepare and
resume. Every selected registry-backed node must belong to the independent
issuer; mixed-issuer endorsement is explicitly refused. Endorsement changes
authentication only, preserving the Grant body, timestamp and nested evidence.
The first staged profile rejects `--refresh`, `--derive` and `--opening`.
Preparation may retain retryable unknown current state when newer evidence is
known; that does not claim acceptance. Resume requires the original local
preparation and unchanged live deadline before importing the endorsed frame.
It never reconstructs a missing preparation or revives an expired Grant.
The auditor still independently verifies current issued state before Admit.

A separate discloser group uses the same exact prepare/endorse/resume sequence.
First complete its accepted group Admit and explicitly provision the existing
registry root to the selected member's encrypted Keeper. Each member runs
`--prepare --send-proposal --consent-lifetime 60 --output prepared.cesr`, with
the creator selecting `--proposal-output proposal.cesr` and contributors selecting
`--proposal proposal.cesr`. `--send-proposal` authorizes signing-member coordination
only; `--deliver` remains forbidden during preparation. The finite consent lifetime
must be selected before the first partial Grant. Existing deadlines are preserved,
and the configured KRAM original-timestamp policy still applies.

Preparation exports only after ordinary group sender signatures verify; it does
not claim credential acceptance or issuer authorization. The independent issuer
endorses the exact aggregate Grant as above. Each member then runs `--resume` with
that endorsed file and the same explicit `--unblind-proposer MEMBER_AID`, selecting
the root-bearing member to author the reply. `--respond-unblind --deliver` approves
that exact live operation. Other members verify and sign the minimum openings
without needing a root, and native signature indices elect delivery. The installed
story covers an individual issuer/holder, a separate 2-of-2 discloser group and a
rootless individual auditor, preserving earlier admitted bodies and proofs.

A holder group uses two finite member processes and explicit proposal consent.
A provisioned nonlead may create the new presentation from its encrypted group
root; DH custody does not select the presentation proposer:

```sh
kli ipex present --name provisioned-member --alias holder-group --version 2.0 \
  --from-grant "$ADMITTED_GRANT" --recipient "$AUDITOR_AID" --disclose a/name/ \
  --refresh --derive --proposal-output presentation-proposal.cesr \
  --output presentation.cesr --deliver --timeout 120
# Keep it running. In the other member's independent store:
kli ipex present --name other-member --alias holder-group --version 2.0 \
  --from-grant "$ADMITTED_GRANT" --recipient "$AUDITOR_AID" --disclose a/name/ \
  --refresh --proposal presentation-proposal.cesr --deliver --timeout 120
```

The contributor selects its exact accepted Grant/local Admit and the same
recipient, message and disclosure plan. It signs the retained Grant bytes,
timestamp and proofs. Without `--refresh`, proofs must match the admitted view;
with it, native accepted history and `vetBinds` verify carried current proofs on
a copy. Contributor `--derive`/`--opening` are rejected because they would replace
the packet. Fuller same-SAID holdings cannot widen the selected view.

`group_proposed` reports the new Grant before threshold completion. Both finite
processes exchange signatures through member mailboxes. Only native threshold
and current-issued acceptance permit output and delivery; each member evaluates
native `Exchanger.lead` independently of who proposed or derived the proof. JSON
reports local acceptance and actual transmission, without claiming a later
Admit. Provision the auditor's public KEL/TEL/schema dependencies explicitly.
Add `--respond-unblind` to both group presentation invocations to approve this
exact outgoing Grant and remain live for query, threshold reply and final Admit.
The original presentation proposer authors the reply; other members verify its
minimal openings without needing a root. Native signature indices still elect
the transmitter independently of the proposer.

A group recipient runs the following finite command in each member's own store:

```shell
kli ipex admit --version 2.0 --name verifier-member --alias verifier-group \
  --said EXACT_GRANT --unblind --unblind-proposer SELECTED_MEMBER_AID \
  --input public-history.cesr --deliver --timeout 120
```

Every invocation explicitly selects the same Grant, message and proposer. The
proposer authors one frozen query and, after current issued verification, one
Admit. Other members contribute to those exact bytes through real member
mailboxes. `--unblind-proposer` grants no root custody, special signature weight
or transmitter authority. Group observer queries remain outside this profile;
each member must have the accepted public history selected by the query.
`/multisig/qry` is a CLI coordination extension: a member-signed native EXN with
`a={gid,qry}` and one committed native query child, including its exact public
event nests. `/multisig/rpy` and `/multisig/exn` carry reply and Admit contributions.
All native query/reply verification uses the live conversation owners, never a
private mux verifier. Partial signatures cannot authorize peer disclosure or
Admit. All waits and deliveries remain bounded by the original Grant deadline.

The native `Unblind` owner separately supports group responders. Each member
explicitly approves the same live Grant and receives the authenticated requester
query. A provisioned member calls `respond(xid)` to prepare a frozen reply and a
`sign` cue; another member calls `contribute(xid, proposal)` after independently
verifying its exact minimal openings. Contribution does not read or copy a root.
The caller feeds these ordinary reply signatures through each member's live
Parser/Revery. Only threshold completion produces a `reply` cue, on the member
with the lowest verified contributing index. Root custody does not elect it.
`complete(xid)` reports reply threshold readiness and the original Grant deadline
still applies.

A responder explicitly calls `finish(xid)` on its completed own reply before
peer delivery when its outgoing Grant still needs those current proofs. This
requires the real authenticated request, the full reply signature threshold,
and the exact minimal verified openings. Ordinary native verification accepts
only that same outgoing Grant; the source admitted proof and original deadline
remain unchanged. A root or a partial group reply cannot authorize completion.
Completion verifies evidence, not permission to use the credential: callers must
still deliver authenticated revoked or vacuous replies without an issued-state
gate. Final application admission remains a separate decision.

A native group requester instead calls `start(grant)` to freeze a query proposal
and its exact accepted public events. Each other member explicitly approves the
same Grant, then `contribute(xid, proposal)` checks that event selection before
signing the unchanged query. Group query proposals use ordinary last-signature
groups, matching native query dispatch; KRAM binds its partial aggregate to
accepted establishment keys. The caller supplies contributions to the live
KRAM/query owner (or a complete ordinary threshold when KRAM is disabled).
Only the verified threshold
emits the elected member's `query` delivery cue. Repeated `start()` returns the
frozen proposal or aggregate; it never renews the original Grant lifetime.
Requester `complete()` remains false until the responder's reply verifies, and
`finish()` still performs ordinary Grant verification. The CLI coordination above
transports these proposals without adding another acceptance or custody owner.

`--respond-unblind` approves this exact outgoing Grant before delivery and
keeps its process alive for native Unblind replies and the selected Admit.
The recipient explicitly selects presentation admission:

```sh
kli ipex admit --name auditor --alias auditor --version 2.0 \
  --said "$PRESENTATION_GRANT" --unblind --input presentation.cesr \
  --deliver --timeout 120
```

Unblind exchanges only event-specific proofs for the selected live Grant.
Reply readiness is followed by native finish, exact Grant acceptance, and a
current native recheck requiring issued state before constructing Admit.
Revoked state cannot authorize Admit. Provide accepted schema and endpoint
dependencies explicitly. Optional `admit --evidence-url HTTPS --evidence-ca PEM`
acquires only the selected registries' authenticated public KEL/TEL evidence
before starting Unblind. `--evidence-hostname` may override an IP URL's certificate
identity. HTTP 404/503 and authentic older prefixes wait within the original
Grant deadline; TLS/authentication errors and conflicting evidence fail.
The native Unblind query therefore selects its head after acquisition. Once
selected, a changed head aborts that operation instead of restarting it.
Both operations preserve native deadlines and abandon live authority on
timeout/cancellation. A fresh process has no recovered Unblind approval.

Inspection uses read-only public database handles and never opens Keeper,
polls, retries escrows or authorizes Unblind:

```sh
kli ipex inspect --name holder --version 2.0 --said "$ADMITTED_GRANT"
kli ipex inspect --name holder --version 2.0 --said "$ADMITTED_GRANT" --current
```

Default JSON reports exact retained bodies/evidence as base64, deadline,
accepted/terminal state and historical observations. `--current` adds only
`reverifyGrant`'s current verdict and observations, or its missing-context error.
Historical observations remain unchanged. Group Unblind and anchored
presentation profiles remain unsupported. Existing default v1 commands remain unchanged.
