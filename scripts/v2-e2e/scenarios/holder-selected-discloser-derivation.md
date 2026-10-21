# S6: holder-selected-discloser-derivation

Issuer, holder, distinct selected presenter and external Dolly. Holder and presenter begin with partial admitted material.

Signed holder consent transfers partial material. The issuer directly provisions only the designated presenter with the scoped registry capability through the protected plaintext R&D adapter. Presenter reopening precedes later-event derivation. Additional material later requires another issuer admission and holder consent grant.

Hooks name the actual presenter. Missing capability, wrong event/credential and wrong recipient/controller fail. Derivation does not reveal withheld attributes; the holder remains without a salt. No encrypted transfer or normative onward delegation is claimed.

Run `./run-linux.sh holder-selected-discloser-derivation.sh` from this directory. The common runner installs
both wheels, starts three witnesses with quorum two, and retains command/service
logs and the exact result manifest in a named Linux volume. See README.md for
transport selection and the explicit plaintext adapter boundary.
