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
Revoked state cannot authorize Admit. Provide accepted KEL/TEL/schema and
endpoint dependencies explicitly; these commands do not fetch missing history.
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
Historical observations remain unchanged. Group and anchored presentation
profiles are unsupported. Existing default v1 commands remain unchanged.
