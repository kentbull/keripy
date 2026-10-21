# Clean published-source qualification — 2026-10-21

The declared optional-custody/standalone-Dolly refactor gates are complete for
this bounded provisional R&D profile. This is a tested reference baseline, not
a production release or an unqualified claim of specification conformance.
No TypeScript work was performed or implicitly authorized by this result.

## Exact source pair and execution

Both repositories were fetched from GitHub into fresh, clean clones before
running the unmodified `scripts/v2-e2e/qualify.sh`. It exited **0**. Source was
copied into Linux images, installed as wheels, and exercised with independent
Docker named volumes. No host source or LMDB state was bind-mounted.

- KERIpy: [`64e14e086f16a4fd02eb9fc02ce07a2236175ca7`](https://github.com/kentbull/keripy/tree/64e14e086f16a4fd02eb9fc02ce07a2236175ca7), branch `v2-e2e`.
- Dolly: [`8da5d718c0255ebd2541c719ca5c7046538d9483`](https://github.com/kentbull/dolly/tree/8da5d718c0255ebd2541c719ca5c7046538d9483), published on `master`.
- Dolly's dependency pins exactly that KERIpy commit. Installed versions are
  `keri 2.1.0.dev1` and `dolly 0.1.0.dev0`.
- Every operator manifest reports both worktrees clean. All six v2 stories use
  the same installed image, with separate identity/state volumes.

## Results

| Gate | Actual result |
|---|---|
| Integrated KERIpy core/application/CLI selection | **986 passed**, 8 warnings, 342.54 seconds |
| Standalone Dolly installed application/process suite | **26 passed**, 2 intentionally skipped released-peer cases, 1 warning, 117.38 seconds |
| Actual separately installed KERIpy 1.2.14 and 1.3.6 peer matrix | **2 passed**, 1 warning, 17.61 seconds; covers the two cases skipped above |
| Dolly v1 Bash operator workflow | Passed: three witnesses/quorum two, issuance, negotiation, local admission, HTTP/TCP grants, two real hooks, then revoked-state refusal and no third hook |
| Six independent v2 Bash stories | All passed; three witnesses/quorum two each, alternating HTTP/TCP, two real hooks per story |

The Python total is **1,014 passed**. The seven Bash workflows are additional
operator evidence, not included in that count. Warnings are the existing
pysodium ctypes-layout deprecation and seven semver deprecation warnings;
there were no test failures. The prior developmental runs and their dirty
manifests remain historical evidence, not substitutes for this clean run.

| Independent story | Dolly transport | Result | Exact public evidence |
|---|---|---|---|
| S1: `holder-full-then-graduated` | HTTP | 2 hooks; passed | [manifest](results/2026-10-21/s1/result.json), [commands](results/2026-10-21/s1/commands.txt), [public streams](results/2026-10-21/s1/public-evidence.tar.gz) |
| S2: `holder-partial-then-onward` | TCP | 2 hooks; passed | [manifest](results/2026-10-21/s2/result.json), [commands](results/2026-10-21/s2/commands.txt), [public streams](results/2026-10-21/s2/public-evidence.tar.gz) |
| S3: `holder-supplied-state-opening` | HTTP | 2 hooks; passed | [manifest](results/2026-10-21/s3/result.json), [commands](results/2026-10-21/s3/commands.txt), [public streams](results/2026-10-21/s3/public-evidence.tar.gz) |
| S4: `holder-provisioned-state-derivation` | TCP | 2 hooks; passed | [manifest](results/2026-10-21/s4/result.json), [commands](results/2026-10-21/s4/commands.txt), [public streams](results/2026-10-21/s4/public-evidence.tar.gz) |
| S5: `holder-selected-discloser-openings` | HTTP | 2 hooks; passed | [manifest](results/2026-10-21/s5/result.json), [commands](results/2026-10-21/s5/commands.txt), [public streams](results/2026-10-21/s5/public-evidence.tar.gz) |
| S6: `holder-selected-discloser-derivation` | TCP | 2 hooks; passed | [manifest](results/2026-10-21/s6/result.json), [commands](results/2026-10-21/s6/commands.txt), [public streams](results/2026-10-21/s6/public-evidence.tar.gz) |

The v1 application-owned [result and transcript](https://github.com/kentbull/dolly/tree/fa63e689efddda5b4fe4fa7a81d8508c3da83f52/docs/results/2026-10-21/v1)
are in Dolly. That story uses Dolly as recipient/verifier and a separate issuer;
it asserts locally authored/verified admits and ordinary subsequent issuer
Parser intake, not an independently observed remote admit acknowledgment.
The focused direct-admission CLI regression separately verifies issuer receipt.

Each result contains actual actor AIDs, exact grant/credential references,
disclosure scope, wheel hashes, public-stream hashes, and received hook bodies.
`commands.txt` is the exact recorded CLI command transcript. Each deterministic
`public-evidence.tar.gz` contains only the CESR files enumerated in its manifest;
all extracted bytes were rehashed against that manifest before publication.
`SHA256SUMS` records hashes of the copied result, transcript and archive for
integrity checking; it is not an externally signed attestation. Secret custody files,
passcodes and private databases are excluded. Event-specific public openings
remain in the proof bundles intentionally.

## Installed artifacts

Wheel archives from separate builds can differ even for the same source pair.
These hashes identify the artifacts actually exercised; no bit-reproducible
wheel-build claim is made.

| Build | KERIpy wheel SHA-256 | Dolly wheel SHA-256 |
|---|---|---|
| Six v2 stories | `3e5739f8b494033d56a1ddcd824d85d2650bee71f96cfbf0dacb18abc4e1751c` | `6192f5070c82f18b40b48fab83dd3533561003aa46f5f4198eff7b0157c89d6b` |
| V1 operator story | `c7b7093e7e329b9ae9caf57493df9dc68fcddbc20504d4b26909a42ef550b3a3` | `6b6ed2c69ef7e97b8a9507d25d4c6e5762651336baf2dec86cdb6e7da8a0431d` |

Local Docker image content identifiers, recorded before any tag reuse:

- Core tests: `sha256:c4eb34276227dc3e3f17acc285fcc8a7bd7bf57049e3cae39ec8193f4604f24b`
- Dolly tests/released peers: `sha256:2098a0565c94540fd73362887b74b5350f1c3bd98b10ff07b62f856dc46b42b4`
- V1 operator: `sha256:52919d95aac883ada6a18fcd8e9b9b62111091e138b1b70f25ea46457f0ced15`
- Six v2 stories: `sha256:080d4c6b98a13a8baa34a5596d8faa3bbf9fa687e0913a3d9978a12ade5a0de2`

These images are local qualification artifacts, not published registry images.
The retained local aggregate log is `/private/tmp/keri-v2-final-qualification.log`,
SHA-256 `c5cc72ac11d57f374e86cbf0e7072d628f082d53390a6cfa000e6ba89f46d88f`. Public scenario evidence is committed above;
private state and full service logs remain in the named Linux volumes.

## What was reused and added

Existing KERIpy cryptography, CESR primitives, KEL/witness processing, EXN,
KRAM, Blinder, LMDB and HIO supplied the foundation. The branch adds substantial
native verification and durable dependency handling, exact grant-specific
section/disclosure retention, holder admission/inventory, registrar/observer
composition, optional derivation custody, real dual-version operator workflows,
and the separately owned Dolly application. Correctness fixes include declared
BLID digest handling, authenticated TEL conflicts, schema/admission context,
KRAM restart/pruning, v1 framing/version propagation, and HIO child lifetime.
It is inaccurate to characterize this as only CLI wiring and a few fixes.

The [provenance guide](provenance.md) and [unit inventory](lineage-inventory.md)
cover 1,139 changed units across 155 files, including 584 production units:
493 live reviewed units and 91 explained removals/moves. The recorded review
covers 67 production files and 39 test files, with no omitted selected units,
stale reviewed source/test/resource hashes, or undocumented selected live
functions at the bounded source snapshot. Uncertain historical origins remain
explicit; a Git author is not automatically an idea's inventor or liable for
our adaptation.

## Remaining boundaries and follow-up work

No acceptance gate remains open in this declared refactor plan. These explicit
limits remain and must travel with any reuse of this reference:

- Use the [provisional profile](profile.md), including documented specification
  conflicts and the source-triple mapping; optional bulk/Merkle profiles remain
  outside its scope.
- Held material, a particular state opening and a derivation salt are different
  capabilities. A salt cannot reconstruct withheld credential attributes.
- Optional provisioning is an owner-only plaintext R&D adapter, not an encrypted
  interoperable transfer protocol or proof of delegated authority. Automatic
  custody AEID migration is not implemented; explicit re-import is recovery.
- Current standing depends on authenticated configured observer/source freshness.
  KEL/TEL anchoring is preserved; no new KRAM timing/snapshot rule or globally
  proven wall-clock publication claim is added.
- Generic graph/presentation-registry APIs and tests exceed the simple grant
  CLI's artifact-construction surface. The v1 source explicitly restarts after
  external authoring to refresh its accepted cache. Webhooks are not a
  distributed exactly-once delivery guarantee.
- Production deployment hardening and a TypeScript port are subsequent scopes,
  not claimed completed here. See [qualification.md](qualification.md) and the
  [handoff contract](typescript-handoff.md) for further limits.

## Reproduction and result-document provenance

Check out the two exact SHAs above, set `DOLLY_SOURCE` to the Dolly clone, and
run `scripts/v2-e2e/qualify.sh`. Choose new `V2_TEST_VOLUME`, `DOLLY_TEST_VOLUME`,
`DOLLY_OPERATOR_VOLUME` and `SCENARIO_VOLUME` names for independent state. The
six stories remain independently runnable through their Bash entry points.

This report, copied public artifacts, and linked completion-status edits were
locally produced by the Codex implementation owner from the recorded execution
on 2026-10-21 under Kent's request. They introduce no runtime function, class,
constant or protocol design. Dolly `8da5d71` differs from the lineage snapshot
`b9aa9d4` only in its dependency pin, verified by Git diff. These later result
commits change documentation/evidence only; they do not falsely claim that the
qualification command ran against their own future commit hashes. The bounded
lineage ledger is preserved instead of creating a circular cross-repository pin.

The later KERIpy documentation units are this report, `qualification.md`,
`refactor-status.md`, `typescript-handoff.md`, and
`scripts/v2-e2e/scenarios/QUALIFICATION.md`. They reconcile status, evidence and
reference scope without changing execution. The generated resource group is
`docs/v2-e2e/results/2026-10-21/s1` through `s6`, each containing exactly
`result.json`, `commands.txt`, `public-evidence.tar.gz` and `SHA256SUMS`.
Artifact capture preserves run output; archive metadata is normalized to stable
file names, mode 0644 and zero timestamps. Provenance is the recorded clean run,
not an upstream author attribution. These explicit entries extend the bounded
ledger for documentation/resources without rewriting its runtime snapshot.
