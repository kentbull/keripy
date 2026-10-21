# Local lifecycle walkthrough

Run from a fresh checkout with Docker available:

```sh
./scripts/v2-e2e/walkthrough.sh
```

`check.sh` builds the pinned Python image, mounts source read-only, and places
temporary and persistent KLI state in separate Docker named volumes. Set
`V2_TEST_VOLUME` to choose their shared name prefix. No companion checkout is
required.

The process demonstration starts three HTTP witnesses, registrar, independent bulk
observer, holder intake, Dolly, and a real HTTP webhook receiver. Separate KLI
invocations create the registry and credential, obtain witness receipts with
issuer and holder quorum thresholds of two,
export public evidence, and negotiate partial then full disclosure through
four complete Apply/Offer/Agree/Grant/Admit sessions: issuer to holder, then
holder to Dolly, for each stage. Every exchange is authored by a KLI subprocess
and delivered over HTTP. The holder presents only its corresponding admitted
grant; it receives the fuller credential only in the second stage. Receiver
acceptance, predecessor/session links, preserved partial views, explicit
admission, and both actual webhook payloads are asserted. Negotiation before
Grant produces no webhook, and Admit does not produce a duplicate.
Holder intake, observer and Dolly restart between disclosure stages.
Public revocation is published and observed before a new presentation;
the issued-state policy emits no acceptance webhook. Stopping the registrar
eventually makes observer queries return stale rather than current evidence.

The focused Dolly socket demonstration additionally checks same-grant replay
privacy, nested and one-way issuer registry references, and a legacy grant
whose conventional TEL replay and signed source TSNs reach the same webhook
contract. An issuance embed alone does not establish current legacy standing.
The source report must be core-authenticated, match the accepted TEL head,
postdate the outstanding request, and remain inside the configured age limit.
These observation facts are application policy, not historical protocol truth.
Only currently configured registrar URLs can establish observer freshness.
Dolly likewise requires an observation from its current observer URL. Reopening
with changed endpoints preserves accepted evidence and old observations, but
requires a new observation from the active endpoint before acceptance.
The two-node graph case runs Apply/Offer/Agree/Grant/Admit over the service
sockets, binds an unchanged grant body into the holder's declared presentation
registry, and verifies ordinary issuer and holder rotations. The application
uses the shared protocol graph evaluator and keeps the unnegotiated block hidden.

The fixture identities and passcode are public test data. These commands do
not establish release readiness, group-flow coverage, or compatibility with
separately installed v1.2.14/v1.3.6 peers; those require their own checks.
Some protocol-rejected submissions remain labelled pending by Dolly's small
application tracker; they produce no acceptance webhook. Advanced graph and
presentation-registry proof authoring in this demonstration uses the Python
APIs; the minimal CLI does not expose every constructor option.

For the full declared profile, including the separately installed old peers:

```sh
./scripts/v2-e2e/qualify.sh
```

The capability map and explicit limits are in
[qualification.md](../../docs/v2-e2e/qualification.md); the exact old-peer source
adapter is described in [legacy-peers.md](../../docs/v2-e2e/legacy-peers.md).
