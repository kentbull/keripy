# Released legacy peers against Dolly

The matrix runs actual published KERIpy **1.2.14** and **1.3.6**, each in its own
Docker process, against current Dolly. It does not use current KERIpy's version
flag to impersonate either release. Qualification on 2026-10-21 UTC used
Linux/arm64 and passed both cases.

| Published peer | Source distribution SHA-256 |
| --- | --- |
| [1.2.14](https://pypi.org/project/keri/1.2.14/) | `f921a42794aa83988987f97d27337da38194dcd7fb0124511374112997660656` |
| [1.3.6](https://pypi.org/project/keri/1.3.6/) | `ed11d636effe1f3ac2a4fc6d5fb6be8d520aebf7951294b9d6801185ff3d230f` |

[profiles.json](https://github.com/kentbull/dolly/blob/89788c5c64feea640b40a9160769fb48c8d8dd54/scripts/legacy-peers/profiles.json) pins download
URLs and hashes; installation verifies the archive before invoking pip.
[Dockerfile](https://github.com/kentbull/dolly/blob/89788c5c64feea640b40a9160769fb48c8d8dd54/scripts/legacy-peers/Dockerfile) pins CPython
3.12.15's image digest. Each release has a complete Python dependency lock,
including HIO 0.6.19 and LMDB 1.7.5. Runtime assertions check the installed
release, Python version, every installed distribution, and the package's
`site-packages` location. Current KERIpy implementation modules are absent from peer containers.
The observed Debian runtime used libsodium23 `1.0.18-1+deb13u1`.

The matrix now belongs to standalone Dolly. From this repository root:

```sh
export DOLLY_SOURCE=/absolute/path/to/dolly
KERI_SOURCE="$PWD" "$DOLLY_SOURCE/scripts/check.sh"
"$DOLLY_SOURCE/scripts/legacy-peers/check.sh"
```

The script builds both peers and runs
[the matrix](https://github.com/kentbull/dolly/blob/89788c5c64feea640b40a9160769fb48c8d8dd54/tests/test_legacy_peer_profiles.py), enabling its explicit
integration-test flag. Ordinary unit runs skip these two cases; the matrix run
executes both and fails if a peer is unavailable. All LMDB files stay in separate
Docker named volumes under `/tmp`; source is copied into Linux images; no host bind mounts are used. The script
prints its run name, removes its containers/network, and retains its named
volumes. No peer opens another version's database.

For each release, its own Habery, Tevery, credential/grant builders, registry
serializer, and HTTP client perform the following real exchanges:

1. Send signed KEL, anchored registry inception, endpoint metadata, and a Grant
   to Dolly's HTTP intake. Public schema content is the only direct receiver
   cache input. Historical issuance verifies but causes no webhook.
2. Receive Dolly's ordinary signed `tels` and `tsn` queries and send conventional
   replay and source-endorsed status replies. Dolly's core BADA acceptance and
   configured source freshness gate the common `dolly.accepted-credential/v1`
   webhook, with `protocol: 1`, issued standing, and the authorized business value.
3. Replay the identical Grant without a second webhook. Publish a real anchored
   revocation, signed current reports, and a fresh Grant carrying the older
   issuance proof. Dolly records revoked standing and rejects that new Grant;
   no second webhook appears. All ten peer-to-Dolly HTTP responses are checked.

Both released `Tevery.processQuery` implementations call `vcState(vcpre=...)`,
although their public method accepts `vcState(vci)`. The matrix first proves that
replay plus the automatic registry notice leaves Dolly pending. Its explicit
[source composition](https://github.com/kentbull/dolly/blob/89788c5c64feea640b40a9160769fb48c8d8dd54/scripts/legacy-peers/peer.py) then calls the
public method positionally and signs its actual core state with `Hab.reply`.
Installed release source is never patched. This qualifies released authoring,
wire formats, core state, and signing with that narrow source adapter; it does
**not** qualify the broken automatic credential-TSN route without the adapter.

The tested topology has one issuer, no backers/witnesses, local HTTP, and
application freshness relative to the configured issuer source. It establishes
neither global latest-state knowledge nor LMDB migration/cross-version opening,
multisig, TLS, or general deployed legacy-daemon compatibility.
