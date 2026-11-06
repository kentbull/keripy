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
holding `{i, ri, gid, rd, s, e[, td]}`. The receiver authorizes from its
accepted KEL/TEL before storing anything: the recipient must be a current
signing member of `gid`; the sender a historical signing member of `gid`, the
registry issuer or a historical member of the issuer group.

Delivery defaults to the recipient's mailbox (topic `credential`, normally its
witness mailbox). `--out FILE` writes the same signed bytes instead, as a
fallback for `receive --message FILE`.

After group DH the custodian sends the root to its other current members; a
group alias defaults to them:

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

The recipient's copy is stored pending in the ordinary exchange store with a
notification; nothing is decrypted until explicit approval. Without
`--registry`/`--said`, `receive` lists pending copies; with one, it approves
that copy, decrypts it, checks the plaintext binding and verifies the root
against a held opening or by reproducing the accepted BUP commitment (using
the `--acdc` hint) before retaining it:

```sh
kli vc registry root receive --name peer --alias holder-group --version 2.0 \
  --registry REGISTRY_SAID --sender LEAD_MEMBER_AID --listen --timeout 120
```

A copy that cannot yet be verified stays pending. A different retained root is
never replaced. Roots never appear in output JSON or in plaintext files.
