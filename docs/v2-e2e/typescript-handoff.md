# Python reference contract for keri-ts

The declared gates closed for the exact source pair in the
[2026-10-21 qualification](qualification-2026-10-21.md). Use that bounded
provisional reference, not an arbitrary later branch tip. This document specifies
responsibilities and observable contracts; it does not authorize changing the
paused TypeScript checkout. No TypeScript implementation was performed.

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
| `app.credentialing`, `app.registry_custody` | Thin issued/admitted inventory and separately optional encrypted registry derivation custody. |
| `app.registrar`, `app.observer` | Authorized hosting and independent bulk synchronization; queries read local verified cache. |
| `app.native_grouping` | Existing group signer, counselor, multiplexor and transport composition with explicit member approval. |
| KERIpy `app.ipexing`; standalone Dolly `dolly.serving`, `dolly.projecting` | Shared protocol dispatch stays in KERIpy; reporting policy, exact disclosure projection and webhook delivery belong to Dolly. |
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
verifiers receive only per-event openings. Ordinary retained-material
presentation and public registry updates require no custody record. A designated
discloser may be separate from the holder; naming that role locally creates no
verifiable authorization or new delegation protocol.

Custody records do not yet participate in automatic Keeper AEID migration.
An old-AEID record blocks the affected derivation operation while ordinary
presentation remains usable with an otherwise authenticated identity. Explicit
re-import encrypts supplied plaintext under the current Keeper; it does not
decrypt and migrate old ciphertext. The optional R&D export is plaintext with
mode-0600 filesystem permissions, not an encrypted transfer envelope. This is
operator provisioning/recovery, not a new IPEX operation or automatic group-secret
distribution mechanism.

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
checks in KERIpy `test_native_services.py` and standalone Dolly
`tests/test_dolly.py` and `tests/test_native_e2e.py` as
acceptance oracles. Test real old peer releases separately from newly generated
protocol-v1 messages.

Dolly's projection is an application view. Undisclosed known business fields are
null with explicit disclosure metadata; an actual disclosed null is different.
No hidden values or richer cached view may enter the projection. Delivery keys
are grant-specific, so a later valid grant can reveal more of the same credential.
No distributed exactly-once delivery promise is made.

## Operator acceptance boundaries

The six independently runnable Bash scenarios in `scripts/v2-e2e/scenarios/`
distinguish initially full holder receipt, initially partial receipt, supplied
state openings, holder derivation custody, and a separate holder-selected
discloser with supplied openings or scoped custody. Those cases use installed
KLI commands and real Dolly hooks. They do not replace the hostile protocol,
group/delegation, revocation, or lifecycle regressions.

Dolly owns the separate `scripts/operator/legacy-v1.sh` workflow: actual v1
issuance, complete negotiation/admission, both HTTP and TCP reporting, and
source-observed revocation. Newly generated v1 wire and separately installed
released peers are distinct qualification gates. Use `scripts/v2-e2e/qualify.sh`
for the composed gates; consult the qualification records for actual results
and exact source/artifact pairs rather than treating these instructions as a
claim that an unrun revision passed.
