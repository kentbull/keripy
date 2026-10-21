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

During construction, S1–S4 and S6 passed their respective real CLI paths.
S6 also passed the concrete required-leaf full plan and secret-output checks. S5 exposed a
stale-known-TEL retry defect: a valid newer opening could return false before the
EXN entered the semantic dependency escrow, preventing Dolly observer refresh.
The script retains the old-head bootstrap and wrong-recipient rejection that
exposed it. It must pass with the repaired receiver; relocating that negative
case does not close the defect. Final qualification results must name completed
runs after the repair rather than infer success from an alternate setup.
