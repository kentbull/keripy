# Individual native IPEX issuance

`ipex grant` and `ipex admit` retain their v1 behavior by default. Native live
issuance is opt-in with `--version 2.0` and requires encrypted, unlocked local
individual habitats. Provision accepted peer KELs, witness/mailbox locations,
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
registry. Groups, anchored Agree/Grant, multi-node/shared-registry profiles,
presentation, Unblind, and provisioning are outside this live issuance unit.
