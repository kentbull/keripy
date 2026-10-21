# Application donor attribution

The registrar and observer application route shapes and service composition are
adapted from KERI Foundation's Apache-2.0 projects:

- [kf-registrar bf14eac4d644275a13cbd3c5900cc2e4dd7c11d1](https://github.com/keri-foundation/kf-registrar/tree/bf14eac4d644275a13cbd3c5900cc2e4dd7c11d1)
- [kf-observer d6368aef9497452f5aa2a0657abe1adf5645c69b](https://github.com/keri-foundation/kf-observer/tree/d6368aef9497452f5aa2a0657abe1adf5645c69b)

Both donor LICENSE files contain the Apache License, Version 2.0, January 2004,
as does this repository's LICENSE. Their duplicated batch validation and
in-memory pending stores are replaced by the common native registry processor.
Observer pulls run independently of cache queries and use cooperative HIO I/O.
Service authorization requires explicit AID allowlists and enabled KRAM.

Research also inspected registered Sally at
`ed789de4aa5f536d5838b4ff0d4d48a4e9dbf525` (Apache-2.0) and Locksmith at
`3a5ad9ebcf98b4ec03baf1bbb91d928d49c168e4`. Locksmith's pyproject declares MIT,
but its pinned LICENSE contains Apache-2.0; do not silently treat the metadata
as a relicensing grant. Neither project is a runtime dependency of these services.

Protocol comparison pins:

- Daniel Hardman's `dhh1128/keripy:feat-edge-operators-next` at
  `dfe59ba1192162b23e9669f11a384a9fc81b9525` was reviewed for edge reductions
  and unknown-state handling. Its configurable Kleene reduction framework was
  not imported. The reference keeps concrete IPEX verification and requires
  the disclosed graph's authentication before applying logical operators.
- Bakobo `feat/far-node-edging` at
  `a93f6d1e1b2c32b5d8b7aa5ada07559e497ed462` was reviewed for separation of
  evidence from edge logic. Its second verifier and unsupported `E1E` operator
  were not imported. Published operators govern this profile.
- Bakobo `sedi-substrate-v4` at
  `910dcb350e63d3129c91345429c1fa10f2dae5e5` informed foreign-intake comparison;
  local and foreign native registry acceptance share the upstream-derived
  engine in this branch.
- Sam Smith's inspected `main` at
  `f9814f8b33234014872b50c2b04e0286c794eeae` and `v2.0` at
  `bf6ce7bc596ec2cc4860f8e392d3b147bd6aa512` are ancestors of the recorded
  upstream starting commit (58 and 364 commits behind, respectively). Their
  integrated work is retained through that baseline, without a redundant merge.

These are exact reviewed inputs, not assertions about the forks' future heads.
