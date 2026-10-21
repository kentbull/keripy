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

## R7: exact blinded-opening digest verification

Targets: `acdc.regeventing.vetBlind`; all constants, the `opening` helper, and
test functions in `tests/acdc/test_blid_digest_profile.py`.

- Inherited implementation: Daniel Hardman's
  `1a2581ba667054e4486388ec99fc0c46bbc5c3c1`, originally
  `acdc.registring.vetBlind`; renamed in
  `11c5c51294bc83eff411701ca03727f37c3081e2`. These are recorded Git authorships.
- Contract: pinned ACDC
  [BLID calculation](https://github.com/trustoverip/kswg-acdc-specification/blob/f0bd097de318fbbe2d069a2b46cecd42550762e3/spec/spec-body.md#calculating-the-said-of-the-serialized-blinded-attribute-block)
  commits to ordered CESR primitive serializations with the digest slot dummied.
  Supported digest codes must serialize to 44 characters. State and bound-number
  primitives retain their permitted original encodings.
- Local correction: Codex implementation and independent Codex review for Kent.
  The anchored `Diger` chooses the digest algorithm; its canonical encoding and
  equality with opening `d` are checked. Verification hashes original primitives,
  replacing only `d`, rather than reconstructing normalized semantic values.
- Review changed the implementation: the initial algorithm-selection repair
  still normalized `NumDex.Long` and `StrB64_L1`. Independent counterexamples
  showed rejection of valid encodings and acceptance of invalid `verify=False`
  objects. The 12 failing exact-encoding cases pass after exact-byte verification.
- Tests are locally designed; SHA-256 also uses Python hashlib as an independent
  oracle. Coverage includes five 256-bit codes, both clans, altered fields,
  invalid/long/trailing digests, placeholder fields, and public empty nonce.
  The 59-case profile and 27 existing registry tests pass in the installed Linux
  wheel. This does not establish R6 conflict policy or complete qualification.
