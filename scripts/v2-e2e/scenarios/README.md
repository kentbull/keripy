# Independent CLI disclosure stories

Run a story from this checkout with Docker Desktop running:

```bash
scripts/v2-e2e/scenarios/run-linux.sh holder-full-then-graduated.sh
```

The runner copies KERIpy and the separately checked out Dolly source into Linux
images, builds and installs wheels, and uses named volumes for LMDB state and
retained diagnostics. It does not mount host state directories. Override
`DOLLY_ROOT`, `SCENARIO_IMAGE`, `SCENARIO_BASE_IMAGE`, or `SCENARIO_VOLUME` as
needed. `SCENARIO_TRANSPORT=tcp` selects the independent Dolly TCP listener;
otherwise the story uses its HTTP listener. Registrar/observer requests use HTTP.

Each story starts three witness processes, uses a quorum of two for issuer,
holder, and selected discloser inception and anchors, and starts separate
registrar, observer, credential receiver, external Dolly, and webhook processes.
Protocol actions appear as individual installed `kli` commands in the story.
`common.sh` only handles identity/endpoint bootstrap, processes, readiness,
assertions, and public service setup. The Python helper handles JSON, sockets,
HTTP readiness, and webhook capture; it imports no KERI or Dolly modules.

The six companion `.md` files describe actors, initial holdings, transfers, and
expected hooks. `run-all.sh` builds one installed image and runs all six stories
with separate named volumes, alternating HTTP and TCP to Dolly. Compatibility,
revocation/staleness and group/delegated qualification remain separate gates.

S1 (`holder-full-then-graduated.sh`) admits one full issuer grant into the
holder's store. After issuer intake stops, the holder independently negotiates a
partial presentation and a full presentation from that same admission. The
webhook checks distinguish withheld private data from disclosed null, verify the
actual holder sender, and check that the earlier retained partial view and hook
stay byte-for-byte unchanged after the fuller presentation. Fuller requests
name all three required leaf paths; they do not treat an empty path as proof of
recursive completeness for arbitrary opaque strings.

A successful run writes `result.json` with AIDs, credential/registry/schema and
grant references, transport, source revisions, and wheel hashes. Command and
service logs remain in the printed diagnostics path, including failures.
Passcodes are fresh process environment values; command logs never contain them.
Test credential payloads and event openings are retained for review. Explicit
custody-transfer stories additionally retain protected plaintext adapter files;
these are an R&D secret-file boundary, not a production custody mechanism.

The opening-only stories use bearer CESR proofs. Such a file authenticates its
credential/event commitment; it does not cryptographically restrict copying to
an intended recipient. Signed IPEX material transfers enforce their addressed
recipient. The local protected custody importer separately checks the accepted
registry controller and intended local designated discloser. Those guardrails
are not signed delegation or authenticated transport. Operators supply the
private-channel and provisioning authority arrangement explicitly.

### Additive KF service profile

Set `SCENARIO_SERVICE_PROFILE=kf`, `KF_REGISTRAR_SOURCE` and
`KF_OBSERVER_SOURCE` to the upgraded fork checkouts, alongside `DOLLY_SOURCE`,
then run the same dedicated story scripts through `run-linux.sh` or `run-all.sh`.
The image installs real `kf-registrar` and `kf-observer` wheels. Their own binaries
serve publication and independent observation; the default `kli` profile remains
unchanged. `Dockerfile.kf` records fork revisions, dirty flags and wheel hashes
in the public result manifest. Linux named volumes continue to own all LMDB.

This selector currently replaces the two registry services only. Witnesses and
wallet actors still use KLI; hosted witness and Locksmith profiles are subsequent
gates. Development runs of the full-holder/HTTP and partial-holder/TCP stories
passed with two Dolly webhooks each. They are integration evidence, not the final
clean multi-component qualification.

### Additive hosted witness profile

Set `SCENARIO_WITNESS_PROFILE=hk` and `WITNESS_HK_SOURCE` to the upgraded
witness-hk checkout. It can be combined with the KF service profile. The runner
installs and launches three independent `witopnet marshal` processes.

This uses the provider's existing per-controller onboarding: incept an actor,
provision one hosted witness in each process, register through `kli witness
authenticate`, then rotate to the three witnesses with quorum two before
credential issuance. Each controller has its own three witness identities.
The result includes their provider mapping and this onboarding history. The
original profile still covers witnessed inception with shared witness identities.

`hosted.sh` drives public CLI operations. `hosted.py` performs boot HTTP calls,
selects exact public introduction frames and generates short-lived headers from
the CLI's registration result. KLI/core verifies all introductions and receipts;
the adapter writes no accepted protocol rows. Test-only TOTP URLs and headers
remain under the owner-only `private/` directory and must never enter public
qualification archives. This is an operator adapter, not a new wallet secret
storage or provisioning protocol.

Development S1 passed with actual hosted provisioning/authorization, issuance,
full-holder graduated presentation and both Dolly hooks. The remaining distinct
stories and final clean installation remain separate gates.

### Additive Locksmith application profile

`SCENARIO_WALLET_PROFILE=locksmith` runs holder and separate-presenter operations
through the installed `locksmith.driver` application adapter. One actual
LocksmithApplication/QtTask owns each actor; public network intake enters its
mailbox parser and outgoing messages use its durable outbox. The issuer remains
KLI in this profile. Manifests name these roles explicitly; do not describe this
as Locksmith issuer end-to-end coverage.

Build the copied-source composition with Locksmith's
`scripts/scenarios/Dockerfile` and its explicit core/Dolly/KF/hosted-witness build
contexts. This retains six dedicated story scripts and the ordinary KLI profile.
Signed controller endpoint introductions replace command-specific delivery
addresses for Locksmith's normal sender. Query setup loads the pinned scenario
schema and configures full-evidence observation. Separate-presenter permission
is explicit local per-credential policy, not inferred from receipt or custody.

All six development-image stories pass with the real upgraded KF services,
three hosted-witness processes and Dolly. S2 additionally used TCP presentation.
Each retained its two hooks and privacy/refusal assertions. Locksmith rejects a
withheld path during compaction, earlier than KLI's protocol-verification refusal;
the test distinguishes those precise outcomes while retaining the no-hook check.
Final clean common pins and live UI acceptance remain separate qualification gates.
