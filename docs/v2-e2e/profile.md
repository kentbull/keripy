# Native ACDC reference profile

This branch implements the declared native Python R&D profile. Python
qualification precedes TypeScript. The exact commit and completed run results
are reported in the final handoff; the reproducible gates and capability map
are in [qualification.md](https://github.com/kentbull/keripy/blob/81964a69e0dd9897c37654e80bb2d9cc7b6e2934/docs/v2-e2e/qualification.md).

## Source pins

Integration branch: `kentbull/keripy:v2-e2e`, created from freshly fetched
WebOfTrust `main` **c7e74adc3129ba36302db32e58056560b0927424** on 2026-10-20.

Published normative source commits (verified against successful Pages builds):

| Document | Revision |
|---|---|
| KERI | `fbdd4a6155e48248873cccd5cf6f79b6b631a021` |
| ACDC | `f0bd097de318fbbe2d069a2b46cecd42550762e3` |
| CESR | `bad6edd84f928fe1e77a722edbdd829e0878377f` |

The document revision label **v1.1** is not a protocol or CESR genus version.
Protocol version, genus version and serialization kind remain separate inputs.
The registered local specification checkouts were older than these published
revisions; they are not the normative pins for this branch.

Donor review: Bakobo `sedi-substrate-v4`
`910dcb350e63d3129c91345429c1fa10f2dae5e5` supplied the foreign-intake comparison.
The receiver uses upstream's shared local acceptance engine rather than copying
that donor's separate acceptance algorithm. Application donor pins and licenses
are in [donor notices](donor-notices.md).

## Approved provisional interpretation

Kent approved this R&D profile on 2026-10-20. It does not resolve contradictory
published specification text or justify an unqualified conformance claim.

* `upd` uses **td**, following the field definition, examples and Python schema.
  The ACDC table/order instead says `ta`; no alias or received-body rewrite is
  permitted. Blinded and unblinded updates share one contiguous history.
* Authors use inner TEL seals `{s: event.n, d: event.d}`. The corresponding KERI
  couple encoding is `-S`; ACDC's `-T` label conflicts with KERI's seal table.
* Receivers recognize `{d}`, `{s,d}` and `{i,s,d}` maps. Every supplied field
  must match the TEL event and registry. Bare strings and arbitrary maps are
  not seal encodings. Inner TEL ordinal and attached KEL source ordinal are
  different values.
* Accepted KEL membership, controller identity and the anchoring event's
  historical witness requirements are necessary. A body row is not accepted
  evidence, and today's witness threshold cannot substitute for the old one.
* Native registry timestamps require microseconds and a numeric UTC offset.
  Received authenticated bytes are never normalized. Ordinals are canonical
  lowercase hexadecimal without leading zeros.
* Native forms follow the detailed message-type definitions: explicit/implicit
  `acm` maps and fixed `act`/`acg`. The contradictory obsolete fixed `acm`
  layout is rejected. A disclosed issuer `rd` may occur inside `a`/`A` when
  no top-level issuer registry is declared.
* For one-way registry binding, the approved provisional attachment is a source
  triple `(registry ID, TEL ordinal, TEL digest)`. The exact accepted referenced
  event must itself bind the presented credential, using its public `td` or a
  verified BLID opening. Registry inception and unrelated updates are not
  sufficient references. The complete anchored history and issuer identity
  still verify. ACDC permits attaching the registry and event reference but
  does not specify this exact CESR mapping; this is an interoperability profile.

References: [ACDC TEL sections](https://github.com/trustoverip/kswg-acdc-specification/blob/f0bd097de318fbbe2d069a2b46cecd42550762e3/spec/spec-body.md),
[KERI seal tables](https://github.com/trustoverip/kswg-keri-specification/blob/fbdd4a6155e48248873cccd5cf6f79b6b631a021/spec/spec-body.md).

## Ownership and observable states

`RegBaser.accept` atomically writes event body, accepted ordinal and head in
one LMDB environment. Baser and RegBaser do not share a transaction. The
synchronous registry engine validates local and foreign events; `Rever` adds
multi-registry foreign dispatch and durable dependency recovery. Only accepted
ordinal membership denotes acceptance. Pending body storage does not.

The parser's unsigned registry messages carry an explicit empty CESR attachment
group. A raw body from `RegistryStore.cloneTel` is a storage/replay body; service
wire composition supplies the foot. Truncated nonempty feet must not dispatch.

Registrar/observer hosting lives under `keri.app`. Intake/control/query policy
requires authenticated callers and explicit allowlists. Bulk synchronization
runs on its own cadence. Verifier queries read local cache only. Observation
age is an application report trusted through the configured service connection,
not cryptographic proof that no newer event exists anywhere.

The initial default deployment intervals are 5-second synchronization and
15-second maximum observation age. They are configurable, not protocol constants.
Secrets belong in encrypted operator custody; only per-event openings reach
verifiers. Explicit consent, accepted EXN, admitted credential, transmitted
message and acknowledged delivery are separate facts.

Historical verification selects an exact TEL head and its verified KEL source
references. It does not filter controller timestamps against a receiver's clock,
freeze a receiver snapshot as protocol authority, or require TEL publication
before first receipt of a request. Later dependency arrival is ordinary evidence
recovery. KRAM authenticates the request and applies its existing timeliness and
replay rules; current credential standing remains a separate application check.
The reviewed KRAM source is v0.7.6 at
[`6ed1ceff4b8a0bc31c1063df12cd17fa54b2784d`](https://github.com/SmithSamuelM/Papers/blob/6ed1ceff4b8a0bc31c1063df12cd17fa54b2784d/whitepapers/kram.md).

## Component test environment

The core-only `scripts/v2-e2e/Dockerfile`, `check.sh` and `requirements.lock`
remain KERIpy tooling. They copy source and run the installed distribution
with Linux named state volumes. Run `scripts/v2-e2e/check.sh` from the repository
root; optional arguments select pytest cases. Cross-repository composition is
owned by the independent experiment repository.

## Whole-block disclosure requests

The local IPEX `dp` interpretation distinguishes `[]` (node presence at any
valid compaction level) from `[""]` (expanded section containers and visible
aggregate member blocks). A hidden aggregate member is structurally a withheld
block and fails the latter request. Ordinary digest-valued attribute scalars
remain allowed: after reception, an unconstrained string is indistinguishable
from a compacted nested block's SAID. Consequently, `[""]` alone is **not proof
of universal recursive completeness**. Compactor cannot infer missing type
information, and a fuller cached view does not fulfill the received disclosure.
Explicit required leaf paths or a schema that requires the relevant block
structure are necessary for stronger guarantees. Existing node-schema validation
already refuses a scalar where that schema requires an object.

This is a provisional implementation contract approved for this R&D profile.
The pinned ACDC [variant/compaction definitions](https://github.com/trustoverip/kswg-acdc-specification/blob/f0bd097de318fbbe2d069a2b46cecd42550762e3/spec/spec-body.md#acdc-variants)
distinguish block-level and deeper expansion; its
[IPEX outline](https://github.com/trustoverip/kswg-acdc-specification/blob/f0bd097de318fbbe2d069a2b46cecd42550762e3/spec/spec-body.md#issuance-and-presentation-exchange-ipex)
is non-normative and does not settle this exact `dp` wire spelling. S1/S2 full
presentation claims must enumerate required paths and expected revealed values
in their material manifests, then assert those values in actual retained/hook
outputs. They cannot treat the empty-string request alone as that evidence.

## Graph and bound-state decisions

The shared graph evaluator uses the published AND/OR/NAND/NOR/AVG/WAVG and
I2I/NI2I/DI2I/NOT profile. AVG/WAVG require explicit application value/acceptance
policy; the verifier cannot invent ecosystem meaning. Actual accepted KEL
inception/approval evidence establishes DI2I delegation. Unsupported operators,
undisclosed required edges and ambiguous section views cannot become truth.
Independent cached sections require explicit commitment/source selection and
never silently widen an IPEX disclosure.

For bound authority, a near issuance in the same relevant issuee KEL is tested
against `(issued.bn, revoked.bn]`. This interpretation relies on the published
issuer assertion that the named issuee event was current when bound. Different
KEL ordinals are not comparable clocks. Earliest matching issuance means the
earliest in the verified selected TEL history or known accepted issuer KEL;
it does not prove globally first publication. A real stale-bound counterexample
and a resealing counterexample delimit these guarantees in the tests.

Issued inventory retains verified original bound coordinates. New bound CLI
updates require an explicit known-current issuee event; historical retries use
the original coordinates. A holder can explicitly refresh a retained grant's
opening using provisioned custody and newly acquired accepted registry evidence.
An explicit bound event is required when new bound metadata is needed.

Observation freshness is tied to the currently configured source URL. Reopening
with a different observer/registrar preserves authenticated history but does not
inherit freshness authority from a removed source. No new KRAM timing rule is
introduced by this application policy.

## Experiment ownership

Cross-repository recipes, external acceptance scenarios and dated evidence are
owned by the independent `keri-v2` experiment repository. They are not required
to run this component. [Pre-extraction record](https://github.com/kentbull/keripy/blob/81964a69e0dd9897c37654e80bb2d9cc7b6e2934/docs/v2-e2e/profile.md) preserves the
historical source and execution scope. The extraction changes ownership only;
runtime dependencies and verification contracts remain unchanged.
