# Scenario qualification scope

`run-all.sh` is the six-story native v2 operator gate. It installs KERIpy and the
external Dolly wheel once, runs separate Bash stories with independent state,
and alternates HTTP/TCP to Dolly. Every successful story retains `result.json`
and exact command/service artifacts in its named Linux volume. Source revisions
and wheel SHA-256 hashes identify the actual run; a checked-out source revision
alone does not certify uncommitted code included in a built wheel.

These six stories establish content availability, explicit state-proof supply,
scoped derivation, and actual third-party sender distinctions. They do not by
themselves qualify the separate legacy v1 path, revocation/staleness behavior,
group/delegated authoring, hostile core cryptographic cases, or storage failure.
Those gates must remain separately named in the integrated qualification ledger.

All six stories passed against one installed working-source build on 2026-10-21,
with explicit required-leaf full plans and secret-output checks. S5 initially
exposed a stale-known-TEL retry defect: a valid newer opening could return false
before the EXN entered the semantic dependency escrow, preventing Dolly observer
refresh. The original old-head bootstrap and wrong-recipient rejection remain
in the passing script; the negative case was not relocated to avoid the defect.
The focused repair is committed in `7e648d3a` and its related profile run passed
336 tests.

That six-story run was developmental evidence, not final clean qualification:
its KERIpy manifest named `157c23cbc8eafb4d81384d5a29919421e2d0e5fe` with
`dirty=true`; Dolly named `89788c5c64feea640b40a9160769fb48c8d8dd54` clean.
The installed wheel SHA-256 values were:

- KERIpy: `9d57afd576146eec7d5d28de7f7021bbe5b89f5cd8e622780424f206cea59c2b`
- Dolly: `79ea2727baa31dc5897e24f6f9df90d7d86f3ca52b884affbbcbaa8f11ed3956`

Final acceptance requires another complete run from the exact clean published
source pair, including the final proof-validation refinements and v1 changes.
Record that pair and its public manifests/transcripts separately; do not relabel
the developmental artifact as clean.
