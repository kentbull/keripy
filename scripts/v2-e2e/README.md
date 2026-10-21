# Installed CLI disclosure scenarios

Set `DOLLY_SOURCE` to the standalone [Dolly repository](https://github.com/kentbull/dolly)
and run from this KERIpy checkout with Docker available:

```sh
export DOLLY_SOURCE=/absolute/path/to/dolly
./scripts/v2-e2e/walkthrough.sh
```

The entry point runs six independently executable Bash stories. It builds actual
KERIpy and Dolly wheels from copied source and uses a separate Linux-owned named
volume for each story. Neither source nor LMDB state is bind-mounted from macOS.
Each story drives installed `kli` and `dolly` commands; Python companions handle
fixture JSON, HTTP capture, and assertions, not hidden protocol authoring.

| Story | Material and authority boundary |
|---|---|
| `holder-full-then-graduated.sh` | Holder admits full material once, then presents partial and fuller disclosures without further issuer messages or salt provisioning. |
| `holder-partial-then-onward.sh` | Holder first receives partial material, cannot reveal withheld leaves, then admits a fuller issuer disclosure before onward disclosure. |
| `holder-supplied-state-opening.sh` | Holder receives event-specific openings; no derivation salt or authority to update registry state is transferred. |
| `holder-provisioned-state-derivation.sh` | Holder explicitly imports per-registry custody and derives an opening for a genuinely later accepted event. |
| `holder-selected-discloser-openings.sh` | Separate presenter admits holder-signed disclosure material and receives specific openings; holder selection does not invent a delegation protocol. |
| `holder-selected-discloser-derivation.sh` | Separate presenter explicitly receives scoped custody; the holder can remain without it. |

Run one story independently:

```sh
./scripts/v2-e2e/scenarios/run-linux.sh holder-full-then-graduated.sh
```

`SCENARIO_TRANSPORT=http` or `tcp` selects direct Dolly delivery. The aggregate
runner alternates transports, shares one installed image, and isolates each
story's identities and databases. Scripts use bounded polling, retain failure
logs, and assert actual webhook content. Their manifests record public artifacts,
exact credential/disclosure paths, actors, registry events, and observed results.
The test passcode and identities are public fixtures. Secret provisioning files
are not public artifacts and must not appear in transcripts or webhooks.

A full-disclosure assertion enumerates the expected leaf paths and values.
The provisional empty-string disclosure request alone cannot distinguish an
arbitrary digest-valued scalar from a compacted nested block.

The original witnessed Python integration remains supplementary regression
coverage in Dolly's `tests/test_native_e2e.py`. Dolly also owns its application,
HTTP/TCP process tests, pinned schemas, and separately installed released-peer
matrix. There is no Dolly application compatibility package in KERIpy.

For the declared core, standalone application, released-peer, and Bash gates:

```sh
./scripts/v2-e2e/qualify.sh
```

`check.sh` is the smaller installed-wheel pytest runner. `V2_TEST_IMAGE` and
`V2_TEST_VOLUME` select isolated image/state names. Qualification results and
remaining gates are recorded in [refactor-status.md](../../docs/v2-e2e/refactor-status.md);
commands being present does not imply every current gate has passed.
See [qualification.md](../../docs/v2-e2e/qualification.md) and
[legacy-peers.md](../../docs/v2-e2e/legacy-peers.md) for capability limits. Registry
observation freshness is configured application policy, and HTTP/TCP delivery
alone is not authenticated recipient acceptance or a production-readiness claim.
