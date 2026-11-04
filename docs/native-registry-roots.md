# Explicit existing registry-root copies

`vc registry provision` and `receive` are opt-in native `--version 2.0` commands
for accepted individual local identifiers with encrypted unlocked Keepers.
They copy an existing issuer-owned root using native RegistrySalt. They create
neither a registry nor a new root, and do not use DH as a fallback.

The sender must already know the recipient's accepted current key state:

```sh
kli vc registry provision --name issuer --alias issuer --version 2.0 \
  --registry REGISTRY_SAID --recipient RECIPIENT_AID --output encrypted-reply.cesr
```

The exclusive-create output contains only the signed encrypted reply. Optional
`--deliver --timeout 120` explicitly submits it through existing recipient
endpoints/mailboxes. Transport completion is reported separately from receipt.

The receiver selects an exact accepted BUP and an already held CESR state
opening for it. Approval and intake occur within the same finite invocation:

```sh
kli vc registry receive --name receiver --alias receiver --version 2.0 \
  --registry REGISTRY_SAID --sender ISSUER_AID --event ACCEPTED_BUP_SAID \
  --opening held-opening.cesr --evidence public-kel-tel.cesr \
  --message encrypted-reply.cesr --timeout 120
```

Use `--listen` instead of `--message` to await ordinary mailbox delivery after
approval. `--evidence` may repeat and accepts only signed public KEL/TEL and
endpoint support, never credential disclosures or root-copy replies. The held
opening file is one exact native BlindState or BoundState CESR primitive.

Only a native successful receipt reports `received: true` with its exact reply
SAID. A saved reply or a root already in the Keeper cannot imply success. An
identical root copy can succeed; a conflicting root cannot replace retained
custody. Roots never appear in output JSON, plaintext files or public TEL.

Timeout/cancellation abandons this process's approval and closes transport.
A restart requires a fresh explicit receive invocation and approval. Group
completion and remote-signing habitats are outside this individual CLI profile.
