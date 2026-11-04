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
The accepted alias must be an individual local signer controlling that registry.
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

Success ends with JSON fields `regid`, `priorHead`, `head`, `sequence` (integer),
`state`, `output`, and `accepted: true`. Earlier progress JSON uses
`accepted: false`. A finite timeout can leave a staged BUP, a signed KEL event,
and an empty reserved output file. An incomplete report identifies that event;
it is not an accepted-head or publication claim. Inspect and resolve the exact
unfinished evidence before retrying. A fresh invocation refuses to append behind
an outstanding staged successor and never silently replaces an existing output.
