# S2: holder-partial-then-onward

Issuer, holder and external Dolly. The holder initially admits only a partial issuer disclosure.

Four separate negotiated sessions supply partial issuer material, present a subset onward, supply fuller issuer material, and present it onward. A requested withheld leaf fails before the second admission. No salt transfers.

Two accepted hooks name the holder. Two distinct holder admissions are retained; an unavailable-field attempt creates no third hook.

Run `./run-linux.sh holder-partial-then-onward.sh` from this directory. The common runner installs
both wheels, starts three witnesses with quorum two, and retains command/service
logs and the exact result manifest in a named Linux volume. See README.md for
transport selection and the explicit plaintext adapter boundary.
