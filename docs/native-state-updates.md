# Native issuer state updates

After native issuance and Admit, update the same credential using its exact
self-verifying body and the issuer's existing encrypted Keeper:

```sh
kli vc registry update --name issuer --alias issuer --passcode "$PASSCODE" \
  --version 2.0 --credential exactbody.cesr --state issued \
  --output issued-public.cesr --timeout 120
```

`--state` selects `issued`, `revoked`, or `vacuous`. Vacuous appends an empty
update and preserves the previous effective credential binding. The registry
comes from the credential's `rd`; there is no independent registry selector.
The accepted alias must be a local signer controlling that registry.
The command requires its retained root, accepted contiguous anchored BUP history,
and a current effective binding to this credential. Ordinary proofs derive from
the root; bound history requires exact held proofs. No root is generated or
provisioned, and a RIP-only registry or outstanding staged successor is refused.

The output is created exclusively before authoring. It contains public KEL and
delegation evidence and full TEL history with verified source attachments. It
contains no credential openings or registry root. Publish it separately through
the selected registrar workflow. Updating a local registry does not itself make
an observer aware of its new head.

The existing witness authorization flags are available: `--authenticate`,
repeatable `--code WITNESS_AID:code`, and `--code-time ISO8601`. The controller's
accepted KEL policy selects interaction or establishment anchoring and ordinary
witness/delegation completion.

A local group member may author an update after explicitly receiving the existing
root through the [provision/receive workflow](native-registry-roots.md). Imported
accepted group registry history requires no new local registry alias. The exact
issuer RIP, accepted BUP history, existing root and current credential binding are
still checked before any successor is staged; membership alone cannot authorize
derivation.

Run the same update command with that member's store and group alias. Leave it
running while the other members invoke `kli multisig join --version 2.0` in their
own stores and explicitly approve the exact proposed BUP and controller anchor.
`group_bup_proposed` identifies both SAIDs. Ordinary group signature thresholds
and witnessed controller completion precede `accepted: true`. Explicit witness
authentication flags are refused for this group profile; its existing group
receipt owner performs witnessing.

The issuer's original Grant is not its own admitted presentation. The actual
holder may receive the new public history and use `ipex present --refresh --derive`
to create a new presentation from its original admitted view. Prior admissions,
credential bodies and held proofs remain unchanged; an independent verifier needs
the verified public evidence and disclosed openings, without a registry root.

Success ends with JSON fields `regid`, `priorHead`, `head`, `sequence` (integer),
`state`, `output`, and `accepted: true`. Staged/incomplete progress JSON uses
`accepted: false`; `group_bup_proposed` reports pending member approval.
A finite timeout can leave a staged BUP, a signed KEL event,
and an empty reserved output file. An incomplete report identifies that event;
it is not an accepted-head or publication claim. Inspect and resolve the exact
unfinished evidence before retrying. A fresh invocation refuses to append behind
an outstanding staged successor and never silently replaces an existing output.
