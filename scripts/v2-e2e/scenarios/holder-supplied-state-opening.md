# S3: holder-supplied-state-opening

Issuer, holder and external Dolly. The holder initially has full credential material and only event 1 evidence.

A genuine witnessed event 2 makes a new opening necessary. The issuer exports that single CESR bearer proof; the operator explicitly supplies its file to the holder. This is neither a recipient envelope nor derivation custody.

Missing, wrong-event and unrelated-credential proofs fail. The correct proof enables partial and fuller hooks. A later genuine event 3 cannot be opened using the supplied event 2 proof or absent custody.

Run `./run-linux.sh holder-supplied-state-opening.sh` from this directory. The common runner installs
both wheels, starts three witnesses with quorum two, and retains command/service
logs and the exact result manifest in a named Linux volume. See README.md for
transport selection and the explicit plaintext adapter boundary.
