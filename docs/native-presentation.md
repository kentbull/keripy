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
Group `--respond-unblind` and group presentation admission are rejected; an
individual recipient can admit complete current proofs using the command below
without requesting auxiliary openings.

The native `Unblind` owner separately supports group responders. Each member
explicitly approves the same live Grant and receives the authenticated requester
query. A provisioned member calls `respond(xid)` to prepare a frozen reply and a
`sign` cue; another member calls `contribute(xid, proposal)` after independently
verifying its exact minimal openings. Contribution does not read or copy a root.
The caller feeds these ordinary reply signatures through each member's live
Parser/Revery. Only threshold completion produces a `reply` cue, on the member
with the lowest verified contributing index. Root custody does not elect it.
`complete(xid)` reports threshold readiness and the original Grant deadline still
applies. Group requester approval is explicitly refused. Member transport/CLI
coordination is a subsequent unit; the CLI restrictions above remain in force.

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
