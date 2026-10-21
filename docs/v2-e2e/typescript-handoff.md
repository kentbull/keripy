# Python reference contract for keri-ts

Port only after the branch's qualification gates close. This document specifies
responsibilities and observable contracts; it does not authorize changing the
paused TypeScript checkout. The exact qualified commit is the SHA reported with
the final qualification result. Resolve it with `git rev-parse HEAD` in the
fresh checkout used for that run.

## Wire and evidence

Use the pinned specification revisions and explicit provisional choices in
[profile.md](profile.md). Preserve protocol version, CESR genus and codec as
independent values. Native credential and section vectors cover JSON, CBOR,
MGPK and CESR; framing tests cover qb64/qb2 and incomplete attachment groups.
A decoded message is not automatically authenticated, accepted or admitted.

Registry `rip`, `bup` and `upd` share one contiguous `n,p` history. Public `upd`
uses `td,ts`; blind openings use the existing `BlindState` or `BoundState`
material. A TEL body on the wire has a complete attachment group, including an
explicit empty group when no attachment is needed. Its accepted controller KEL
anchor supplies authentication. Match every field of a supplied supported seal.
An unresolved unsigned source locator is a discovery hint, never persistent
authority capable of poisoning a later authentic replay.

A credential without an embedded issuer registry may use the approved source
triple `(registry ID, TEL ordinal, TEL digest)`. The exact event must bind that
credential. This is distinct from a TEL's KEL-source locator. Hidden issuer
registry declarations in disclosed attributes use the same binding verifier.

Historical presentation selects the exact authenticated TEL head/source in its
proof. KRAM retains its request timeliness and replay semantics. There is no
new TEL-before-receipt rule, receiver snapshot protocol, or controller-clock
cutoff. Current standing is a separate policy based on an independently acquired
known head and an explicit freshness limit. Bound-state ordering within an
issuee KEL retains the documented issuer-current-event premise; it does not
prove global wall-clock publication.

## Port boundaries

| Python reference | TypeScript responsibility |
|---|---|
| `core.serdering`, `acdc.messaging` | Native forms and exact commitment construction/validation; preserve received bytes. |
| `core.parsing`, `acdc.sectioning` | Dispatch, counted framing, durable missing-section resolution, exact received disclosure views. |
| `acdc.regeventing` | One local/foreign chain, anchor, blind, bound and target-binding verifier; no I/O or application policy. |
| `acdc.regbasing`, `acdc.registering` | Atomic accepted ordinal/body/head writes and durable dependency escrows. |
| `acdc.scheming`, `acdc.ipexing` | Schema identity and one authenticated DAG evaluator; native IPEX semantics. |
| `peer.exchanging` | Authentication, escrow and retained exact accepted grant view; new fuller disclosure uses a new exchange. |
| `app.credentialing` | Encrypted private custody, issued inventory, explicit admission references. |
| `app.registrar`, `app.observer` | Authorized hosting and independent bulk synchronization; queries read local verified cache. |
| `app.native_grouping` | Existing group signer, counselor, multiplexor and transport composition with explicit member approval. |
| `app.dolly`, `app.ipexing` | Version dispatch, current-standing/disclosure policy and actual webhook delivery. |
| `cli.common.native`, `cli.common.native_exchange` | Operator workflows and truthful pending/accepted/transmitted/admitted output. |

Reuse the existing TypeScript equivalents where they already own a responsibility.
Do not create a second verifier, generic workflow bus, shared protocol lock, new
payload archive or durable delivery infrastructure to mirror this table.

## Storage and custody

Accepted native registry state remains in RegBaser's `evts.`, `tels.` and `heds.`;
`ancs.` is a revalidated locator cache. `maes.` and `ooes.` retain dependencies.
One RegBaser transaction owns acceptance. KEL Baser, private wallet and service
observation stores are separate environments; no cross-environment atomicity is
promised. Pending bodies never imply accepted ordinal membership.

Wallet records use `custody.`, `issued.`, `admitted.` and `credential-grants.`.
Custody includes the designated controller/discloser and exact derivation
parameters. The long-lived salt is encrypted under the authenticated Keeper;
verifiers receive only per-event openings. AEID changes require explicit
operator rewrap/import. Protected export/import is an operator step, not a new
network protocol or automatic group-secret distribution mechanism.

Section evidence uses `msgs.`, `parts.`, `views.`, `required.`, `pending.` and
`failures.`. A raw-view digest distinguishes disclosures sharing the same ACDC
commitment. Ambiguous partial section candidates require an explicit source
message SAID; resolution never merges disclosures into a grant or webhook.

These are reference schemas and invariants, not a claim that older Python or
TypeScript can open the same LMDB directory. Qualify wire interoperability
before proposing shared database compatibility.

## Reusable tests and application contract

Port the vectors from `tests/acdc/test_native_registry_profile.py`,
`test_native_forms_profile.py`, `test_registry_binding_forms.py`,
`test_native_graph_profile.py`, `test_bound_state_profile.py` and
`tests/core/test_native_registry_framing.py`. Retain the adversarial histories in
`test_registry_arbitration.py`, `test_observing.py` and
`test_historical_evidence.py`; a successful happy-path replay cannot replace them.

Use `tests/app/test_native_wallet.py` and `test_native_ipex_cli.py` for explicit
consent, retained proofs and reopen behavior. Use the actual socket/process
checks in `test_native_services.py`, `test_dolly.py` and `test_native_e2e.py` as
acceptance oracles. Test real old peer releases separately from newly generated
protocol-v1 messages.

Dolly's projection is an application view. Undisclosed known business fields are
null with explicit disclosure metadata; an actual disclosed null is different.
No hidden values or richer cached view may enter the projection. Delivery keys
are grant-specific, so a later valid grant can reveal more of the same credential.
No distributed exactly-once delivery promise is made.
