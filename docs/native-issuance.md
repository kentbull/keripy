# Native IPEX issuance

`ipex grant` and `ipex admit` retain their v1 behavior by default. Native live
issuance is opt-in with `--version 2.0` and requires encrypted, unlocked local
signers. Issuers and holders have the explicit group profiles below. Provision accepted peer KELs, witness/mailbox locations,
and schema evidence first. The commands borrow native Regery, Exchanger, DH,
and the existing witness/delegation and mailbox owners.

Create a fresh native registry and its public body using the existing commands:

```sh
kli vc registry incept --name issuer --alias issuer --version 2.0 --registry-name fresh
kli vc create --name issuer --alias issuer --version 2.0 --registry-name fresh \
  --recipient "$HOLDER_AID" --data '{"role":"reader"}' --output body.cesr
```

Start the issuer and leave it running. `--credential` reads that exact raw CESR
body file; it does not look up a credential inventory. `--issue` authorizes DH
and the subsequent registry issuance. `--deliver` explicitly authorizes sending
through the recipient's accepted endpoint/mailbox records.

```sh
kli ipex grant --name issuer --alias issuer --version 2.0 \
  --credential body.cesr --recipient "$HOLDER_AID" --issue --deliver \
  --input holder-public.cesr --output grant-public.cesr --timeout 120
```

The first JSON line reports the signed `grant` SAID and transaction `xid` before
waiting. Further phase lines report `dh_complete` and issuer-side
`registry_witnessed`. In another process, the holder selects that exact Grant. Invocation
authorizes only that transaction's DH and an Admit conditional on native
verification of its issued, witnessed registry update:

```sh
kli ipex admit --name holder --alias holder --version 2.0 \
  --said "$GRANT_SAID" --input grant-public.cesr --deliver --timeout 120
```

For a holder group, run one finite Admit command per independent member store.
Each command must select the same accepted group KEL event SAID, its elected
custodian member AID, exact Grant and human message:

```sh
kli ipex admit --name holder-member-1 --alias holder-group --version 2.0 \
  --said "$GRANT_SAID" --input grant-public.cesr --deliver --timeout 120 \
  --coordinator "$GROUP_EVENT_SAID" --custodian "$CUSTODIAN_MEMBER_AID"
# In the other member's process, use its own --name and the same selection.
```

The invocation approves only this transaction's native DH contributions and one
matching Admit; it opens no additional consent prompt. Both members remain live.
The elected custodian performs DH and retains the encrypted Keeper root. Other
members verify the original issuer-signed Grant with completed public proofs,
then sign the custodian's retained Admit bytes. They never finish DH or obtain a
root. Ordinary group threshold verification precedes final transmission by the
native exchange's elected transmitter. Other members report `transmitted: false`
and `contributed: true`; DH custody does not select the Admit transmitter.
`group_dh_proposed` marks the custodian's partial reply awaiting contributions.
The CLI coordination extension `/multisig/ipex-proof` carries that exact original
Grant and its completed public opening from the selected custodian. It preserves
the issuer authentication, disclosed bodies, existing evidence and original
deadline; the nonlead independently verifies accepted witnessed registry evidence
before retrying native Grant acceptance. It does not authorize disclosure changes
or enrich an already admitted Grant.
The standalone `multisig join` endpoint-role approval cannot approve DH replies.
Timeout/cancellation abandons this process's operation; a restart requires fresh
explicit selection and cannot recover lost ephemeral keys. Signed observer
queries and group Unblind/presentation are outside this group issuance profile.

For a group issuer sending to an individual holder, first use native registry
inception and the other members' existing `multisig join --version 2.0` to accept
the exact RIP and controller anchor. Create the public credential body in the
elected custodian's managed registry. The fresh Grant author must be that existing
custodian; these options do not elect a new one.

```sh
# Leave the custodian process running through the holder's verified Admit.
kli ipex grant --name issuer-member-1 --alias issuer-group --version 2.0 \
  --credential body.cesr --recipient "$HOLDER_AID" --issue --deliver \
  --coordinator "$GROUP_EVENT_SAID" --custodian "$CUSTODIAN_MEMBER_AID" \
  --consent-lifetime 120 --proposal-output proposal.cesr \
  --input holder-public.cesr --output grant-public.cesr --timeout 120
# Another member independently selects the exact packet and the same scope.
kli ipex grant --name issuer-member-2 --alias issuer-group --version 2.0 \
  --credential body.cesr --recipient "$HOLDER_AID" --issue --deliver \
  --coordinator "$GROUP_EVENT_SAID" --custodian "$CUSTODIAN_MEMBER_AID" \
  --consent-lifetime 120 --proposal proposal.cesr --input holder-public.cesr --timeout 120
```

Each member validates the accepted RIP directly; only the custodian needs a
managed registry alias. The command approves that exact Grant and one unchanged,
authenticated custodian DH query. Ordinary signature thresholds precede native
query transmission. A nonlead reports `phase: contributed`, creates no DH keys or
registry root, and exits. Its store is then available for `multisig join`, which
separately prompts for the exact BUP and controller anchor. The custodian remains
live until native accepted BUP, witnessed anchor, issued credential opening and
the selected holder's verified Admit all succeed. The holder uses the individual
Admit command above, with the group and member public KEL evidence available.

`--consent-lifetime` is a required finite policy for a group issuer's first partial
Grant escrow, separate from `--timeout`. Set it before the first intake. Existing
deadlines never renew, including retries with a larger value. Ordinary configured
KRAM original-timestamp windows still govern wrapper and Grant authentication
and may expire earlier. The library's default ten-second fallback stays unchanged.
`/multisig/qry` is this CLI's scoped coordination extension carrying the native
DH query, not a new auxiliary protocol. Root provisioning/receipt after issuance
uses the existing separate commands; this flow ends at verified Admit.

Both parties may use these group profiles together. Each side independently
selects its own accepted coordinator event and existing elected custodian; the
issuer members approve the exact Grant/query and BUP anchor, while holder members
approve the native reply and exact Admit. Only each party's elected custodian
retains the established root until separate explicit member provisioning. Choose
the original conversation policy before the first partial Grant; neither another
member nor a longer command timeout renews it. The installed two-member-per-party
case covers this issuance composition through witnessed BUP and group Admit;
independent accepted rotations remain separate qualification work.

Optionally require a configured observer to supply the selected registry's
public evidence before Admit:

```sh
kli ipex admit --name holder --alias holder --version 2.0 \
  --said "$GRANT_SAID" --deliver --timeout 120 \
  --evidence-url https://127.0.0.1:5642 --evidence-ca observer-ca.pem \
  --evidence-hostname observer.example
```

The actual selected holder signs a standard `tels` query with `q.i` naming the
registry. HTTPS requires the explicit CA file; a certificate hostname override
is allowed only when the URL uses an IP address. Redirects, authentication/TLS
errors, conflicting or malformed evidence fail immediately. HTTP 404/503 and
authentic older prefixes retry with a bounded cooperative delay. JSON phase
`evidence_waiting` identifies the exact Grant, XID, registry and wait reason.

Evidence must contain one complete ordered selected RIP/BUP history and its
verified public KEL support. Native strict KEL/registry owners independently
verify acceptance; no source header or timestamp supplies freshness authority.
An older authentic prefix cannot authorize Admit or roll back the local head.
A newer authentic head enters ordinary native verification and may prevent
Admit if revoked or not openable as issued. Every acquisition wait rechecks the
original native Grant lifetime; a longer CLI timeout cannot extend it.

`--input` may repeat for signed public KEL/TEL/IPEX evidence. A Grant received
through a mailbox still requires explicit `admit --said` selection. An optional
Grant `--prior` selects an exact accepted native Apply or Agree and preserves
the original transaction XID. The agreed plan must match the disclosed body.
Issuer witness authorization uses the same `--authenticate`, repeated
`--code AID:code`, and `--code-time` options as native registry inception.

Optional `--output` exclusively creates a public evidence file and appends
completed public evidence during the live operation. It never exports roots
or ephemeral private keys. `--timeout` bounds the whole operation and does not
extend the native Grant deadline. Timeout/cancellation closes owned transports;
already accepted public evidence and any completed issuance remain durable.
Keep both processes running: restarting a command cannot recover DH ephemeral
keys or revive a timed-out operation. Select a new fresh registry/transaction
when an incomplete operation cannot finish.

This command supports one disclosed credential in one fresh issuer-controlled
registry. Anchored Agree/Grant, multi-node/shared-registry profiles,
presentation, Unblind, and provisioning are outside this live issuance unit.
