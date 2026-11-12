# Registry root replication (local profile)

`kli vc registry root send|receive|newcomers` replicate an existing,
DH-negotiated registry root so every current member of a holder or issuer group
can use it. They are opt-in `--version 2.0` commands for accepted local signers
with encrypted unlocked Keepers. This is a KERIpy local profile, not a KERI or
ACDC standard.

Each copy is one bare v2 `exn` (`x`/`p` empty) on route `/registry/root`, signed
by the sending member's individual habitat and addressed (`ri`) to one
individual member. Its `a` is `{essr, gid, rd}`: the Blake3-256 digest of an
attached ESSR payload, the AID the root is held for and the registry SAID. The
payload is a libsodium sealed box to the recipient's current first signing key
holding `{i, ri, gid, rd, s, e[, td]}`. Authorization uses the accepted
KEL/TEL: the recipient must be a current signing member of `gid`; the sender a
historical signing member of `gid`, the registry issuer or a historical member
of the issuer group. On arrival the receiver refuses, and stores nothing, a
copy that can never be retained (bad shape or digest, a recipient that is not
a local individual habitat, sender equal to recipient, or a membership or
sender failure against complete local state).

Received copies are accepted automatically; there is no approval step. A copy
that verifies on arrival (full authorization, decryption, plaintext `i`/`ri`/
`gid`/`rd` binding, and the root checked against a held opening or by
reproducing the accepted BUP `b` commitment with the `td` hint) is retained at
once. A copy that cannot verify yet because local state is missing (the
registry TEL, a KEL, the local group habitat, the group rotation that adds the
recipient, or opening evidence) is stored and escrowed, then retried by the
ordinary escrow loop (`Exchanger.processEscrow` drives
`RegistryRoot.processEscrows`). The escrow has no timeout: a copy stays pending
until it is retained or refused, so an offline newcomer never needs a resend. A copy refused on any attempt is dropped from the escrow; the
signed exchange itself stays in the exchange store. A newly retained root adds
one informational notification (`/exn/registry/root`).

Delivery defaults to the recipient's mailbox (topic `credential`, normally its
witness mailbox). `--out FILE` writes the same signed bytes instead, as a
fallback for `receive --message FILE`. A copy is correct whenever it arrives,
so KRAM exempts `exn` route `/registry/root` by default, like the OOBI reply
routes; no KRAM configuration is needed. Replays are harmless: the exchange
store is keyed by SAID, a stored SAID adds no second notification, and a
retained root never changes.

This is the first application-route ESSR payload, and the first ESSR carried
through a witness mailbox, in KERIpy; upstream ESSR is the `/essr/req` direct
transport envelope.

## Automatic copies

Group commands send copies without being asked, on a fire-and-forget happy
path:

- **Group issuance.** Once the issuance completes, so the root is retained and
  an accepted, issuer-anchored BUP exists, the DH custodian sends a copy to
  every other current signing member: the issuer custodian in
  `kli ipex grant` after the verified Admit, the holder custodian in
  `kli ipex admit` after its Admit completes.
- **Accepted group rotation.** After `kli multisig rotate` or
  `kli multisig join` sees a v2 group rotation accepted, every signer of it
  that held a key in the prior establishment and holds roots for the group
  sends each root to every current signing member that is new in that rotation
  or whose contributing key changed. Receivers decrypt only with their current
  key, so a rotated member needs a copy sealed to its new key.

Each copy carries a verification hint derived for its own registry: the ACDC
of the head BUP's locally held opening, else an ACDC of that registry disclosed
by a locally stored IPEX Grant. `--acdc` overrides it on the manual commands.
Before sealing, the sender checks that its own root reproduces the BUP with the
hint and refuses otherwise. Each outcome is printed as a `root_copy` JSON line.

Limits: there is no acknowledgement, sent-copies record or retry. A copy that
cannot be sent, because the mailbox is unreachable, the command's remaining
time runs out or no local opening or Grant yields a hint (for example a member
that holds only a received copy), is reported with
`kli vc registry root send` as the recovery and never fails the issuance or
rotation. Several signers may send the same root; receiving is idempotent, so
duplicates are harmless. A crash between retention and sending leaves the root
unreplicated until someone sends it by hand. The Dhke `replicate` cue is
unchanged for runtimes that persist owed copies.

## Manual copies

After group DH the custodian can send the root to its other current members
by hand; a group alias defaults to them:

```sh
kli vc registry root send --name lead --alias holder-group --version 2.0 \
  --registry REGISTRY_SAID --acdc ACDC_SAID
```

The registry issuer can also copy a root to a holder member (`--holder` names
the holder AID, `--recipient` the member). After an accepted group rotation
that adds members, any holder sends every held group root to each newcomer;
the rotation's witnesser is the default sender:

```sh
kli vc registry root newcomers --name lead --alias holder-group --version 2.0 \
  --rotation ROTATION_SAID
```

`receive` ingests copies and lets the handler retain them. `--listen`
processes the `/credential` mailbox until the root for `--registry` is
retained; `--message FILE` parses a file copy through the same path. Each run
then retries escrowed copies once, prints the copies still pending, and fails
when `--registry` names a root that is not retained:

```sh
kli vc registry root receive --name peer --alias holder-group --version 2.0 \
  --registry REGISTRY_SAID --listen --timeout 120
```

`--said SAID` with `--event` and `--opening` manually retries one stored copy
with evidence it lacks, such as a held opening when no `td` hint was sent. A
different retained root is never replaced. Roots never appear in output JSON
or in plaintext files.
