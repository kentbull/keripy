# S5: holder-selected-discloser-openings

Issuer, holder, distinct selected presenter and external Dolly, each with its own AID/store. The holder initially admits full material.

A signed holder grant and presenter admission record consent/material transfer. Under the issuer-consistent designation, the issuer supplies only an event-specific bearer opening via explicit operator file handoff. No salt transfers or delegation protocol is claimed.

The presenter signs both partial and fuller negotiations, and both hooks name that actual presenter. Wrong recipient/material and wrong proof cases fail; neither participant can derive event 3 from the event 2 opening.

Run `./run-linux.sh holder-selected-discloser-openings.sh` from this directory. The common runner installs
both wheels, starts three witnesses with quorum two, and retains command/service
logs and the exact result manifest in a named Linux volume. See README.md for
transport selection and the explicit plaintext adapter boundary.
