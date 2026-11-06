# Explicit existing registry-root copies

`vc registry provision` and `receive` are opt-in v2 ACDC `--version 2.0` commands
for accepted local identifiers with encrypted unlocked Keepers.
They copy an existing authorized root using v2 ACDC RegistrySalt. They create
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
opening file is one exact v2 ACDC BlindState or BoundState CESR primitive.

For a 2of2 group copying its existing root to another member, the elected
root-owning member prepares the ciphertext once. Select its exact accepted
group KEL coordinator event and the target member's current encryption AID:

```sh
kli vc registry provision --name root-owning-member --alias holder-group --version 2.0 \
  --registry REGISTRY_SAID --recipient GROUP_AID --target TARGET_MEMBER_AID \
  --coordinator GROUP_EVENT_SAID --output owner-reply.cesr \
  --proposal-output custodian-proposal.cesr
```

`--output` remains a v2 encrypted reply, initially carrying only the owner's
group contribution. `--proposal-output` is its authenticated `/multisig/rpy`
envelope. Copy that encrypted proposal file to the other member. Its separate
invocation explicitly approves the exact retained ciphertext and scope:

```sh
kli vc registry provision --name other-member --alias holder-group --version 2.0 \
  --registry REGISTRY_SAID --recipient GROUP_AID --target TARGET_MEMBER_AID \
  --coordinator GROUP_EVENT_SAID --proposal custodian-proposal.cesr \
  --output contributor-reply.cesr
```

The contributor needs no root. It signs the retained reply body, preserving its
timestamp/ciphertext and original signatures. `contributed: true` establishes
neither v2 threshold acceptance nor receipt. It never prepares another root
or ciphertext. Optional `--deliver` submits v2 replies to the selected target.

The target member then approves and receives within one finite process:

```sh
kli vc registry receive --name other-member --alias holder-group --version 2.0 \
  --registry REGISTRY_SAID --sender GROUP_AID --event ACCEPTED_BUP_SAID \
  --opening held-opening.cesr --message owner-reply.cesr \
  --message contributor-reply.cesr --timeout 120
```

Repeated `--message` files must contribute to the same exact reply body. A full
aggregate can also succeed alone. The v2 Revery decides the ordinary group
threshold; v2 ACDC RegistrySalt decrypts through this member's local habitat and
retains under the group AID only after verifying the approved opening. A partial
reply alone cannot retain a root; live `--listen` reports `awaiting_signatures`.
Do not open a contributing command on a member's store while its receive process
is still running. Finish or cancel it, then invoke a fresh explicit receive.

Only a v2 ACDC successful receipt reports `received: true` with its exact reply
SAID. A saved reply or a root already in the Keeper cannot imply success. An
identical root copy can succeed; a conflicting root cannot replace retained
custody. Roots never appear in output JSON, plaintext files or public TEL.

Timeout/cancellation abandons this process's approval and closes transport.
A restart requires a fresh explicit receive invocation and approval. This is an
existing-root copy, with no issuance operation or synthetic Grant deadline.
Remote-signing habitats, group presentation and group Unblind remain separate.
