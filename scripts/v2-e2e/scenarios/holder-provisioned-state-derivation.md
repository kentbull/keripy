# S4: holder-provisioned-state-derivation

Issuer, designated holder and external Dolly. The holder initially admits partial material and has no registry salt.

The issuer exports only this registry capability using the protected plaintext R&D file adapter. Wrong recipient/controller imports fail; explicit correct import and holder reopening enable event 2 derivation.

A partial hook succeeds without a newly supplied issuer opening. Derivation cannot invent a withheld leaf; a second issuer admission is needed before the fuller hook. The salt never appears in hooks or command transcripts.

Run `./run-linux.sh holder-provisioned-state-derivation.sh` from this directory. The common runner installs
both wheels, starts three witnesses with quorum two, and retains command/service
logs and the exact result manifest in a named Linux volume. See README.md for
transport selection and the explicit plaintext adapter boundary.
