# Native lifecycle provenance and design lineage

This ledger distinguishes source lineage, local design, recorded Git authorship,
and implementation/review work. A Git author is not automatically the inventor
or the party responsible for later adaptations. Unknown origins remain explicit.
Coverage is in progress; this document does not yet account for the full branch.

## INFRA-01: copied Linux test source

Targets: `scripts/v2-e2e/Dockerfile`, `scripts/v2-e2e/check.sh`, and
`scripts/v2-e2e/legacy-peers/check.sh` (module-level build/run instructions).

- Origin: these files entered this branch in
  [`44b336798747f306886ac87b82565d5eaac21a4d`](https://github.com/kentbull/keripy/commit/44b336798747f306886ac87b82565d5eaac21a4d),
  recorded Git author Kent Bull. That metadata alone does not establish the
  original idea's author. The pinned base image/dependency choices are retained.
- Classification: local operational adaptation, implemented by Codex for Kent's
  explicit Docker/LMDB isolation requirement; not a KERI/ACDC protocol rule.
- Change: copy source, tests, scripts, static resources, and test configuration
  into Linux image storage and install the actual KERIpy wheel. Remove source
  bind mounts from both runners; released-peer images already contain their
  service program. `V2_TEST_IMAGE` selects an isolated image tag for scoped runs.
- Rationale: source access and LMDB state must not require macOS-host bind mounts
  during qualification. Installed-wheel testing also exposes packaging failures
  that a source-only `PYTHONPATH` can hide.
- Validation: five distinct-index tests and both real released-peer cases pass
  with the copied-source runner. See `refactor-status.md` for exact commands.
- Boundary: named test volumes remain local operational state. This change does
  not claim to fix macOS resource accounting or establish cross-version database
  compatibility. Dockerfiles retain existing licensing/source attribution.

## Documentation ownership

`refactor-status.md` and this ledger are locally authored by Codex under Kent's
documentation/provenance requirement. Reported execution results come from the
specified commands. Retrospective origin research must cite evidence rather
than silently attributing local implementation decisions to specification authors.
