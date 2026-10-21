#!/usr/bin/env bash
# S6: distinct holder-selected presenter receives scoped salt and admitted material.
set -Eeuo pipefail
source "$(dirname -- "$0")/common.sh"
AUTHORIZATION_PROFILE="Signed holder consent grants material to distinct presenter; issuer provisions only this registry salt directly to designated presenter; holder receives no salt; protected plaintext R&D adapter, not delegation or encrypted transfer protocol"
DISCLOSER_ROLE=presenter
prepare holder-selected-discloser-derivation

# The only credential issuance. Blinded issuer custody is explicitly provisioned.
k issuer vc registry incept --v2 -a issuer -r r --with-custody --discloser "${AIDS[presenter]}"
REGISTRY=$(value "$RUN_DIR/latest-issuer.jsonl" registry)
python "$JSON" attributes "$RUN_DIR/attributes.json" "$(kli nonce)" "$(kli nonce)" "$(kli nonce)" "$(kli nonce)"
k issuer vc create --v2 -a issuer -r r --recipient "${AIDS[holder]}" --data "@$RUN_DIR/attributes.json"
CREDENTIAL=$(value "$RUN_DIR/latest-issuer.jsonl" credential)
value "$RUN_DIR/latest-issuer.jsonl" update > "$RUN_DIR/issued-update.ref"
k issuer vc export --v2 -a issuer -r r -s "$CREDENTIAL" --output "$RUN_DIR/credential.json"
SCHEMA=$(value "$RUN_DIR/credential.json" 's.$id')
k issuer vc export --v2 -a issuer -r r -s "$CREDENTIAL" --kels --tels --output "$RUN_DIR/public.cesr"
python "$JSON" plan "$RUN_DIR/partial-plan.json" "$SCHEMA" partial
python "$JSON" plan "$RUN_DIR/full-plan.json" "$SCHEMA" full
services

# First negotiated issuer-to-holder admission reveals only the status block.
k holder ipex apply --v2 -a holder -r "${AIDS[issuer]}" --plan "@$RUN_DIR/partial-plan.json" --endpoint "$ISSUER_ENDPOINT"
APPLY_ISSUER=$(value "$RUN_DIR/latest-holder.jsonl" exchange)
k issuer ipex offer --v2 -a issuer -r "${AIDS[holder]}" -s "$CREDENTIAL" --prior "$APPLY_ISSUER" --disclose a/status/ --endpoint "$HOLDER_ENDPOINT"
OFFER_ISSUER=$(value "$RUN_DIR/latest-issuer.jsonl" exchange)
poll accepted_exchange holder "$OFFER_ISSUER"
k holder ipex agree --v2 -a holder -s "$OFFER_ISSUER" --endpoint "$ISSUER_ENDPOINT"
AGREE_ISSUER=$(value "$RUN_DIR/latest-holder.jsonl" exchange)
k issuer ipex grant --v2 -a issuer -r "${AIDS[holder]}" -s "$CREDENTIAL" --prior "$AGREE_ISSUER" --disclose a/status/ --endpoint "$HOLDER_ENDPOINT"
HELD=$(value "$RUN_DIR/latest-issuer.jsonl" exchange)
poll accepted_exchange holder "$HELD"
k holder ipex admit --v2 -a holder -s "$HELD" --endpoint "$ISSUER_ENDPOINT"
assert_json "$RUN_DIR/latest-holder.jsonl" admitted true
printf '%s\n' "$HELD" > "$RUN_DIR/held-grant.ref"

# The holder explicitly selects and transfers only its current partial material.
PRESENTER_ENDPOINT="http://127.0.0.1:${PORTS[presenter]}/ingest"
# The independent presenter acquires public issuer/TEL dependencies itself.
k presenter vc registry query -a presenter --endpoint "$OBSERVER_URL" --registry "$REGISTRY" --output "$RUN_DIR/presenter-public.cesr"
k holder ipex grant --v2 -a holder -r "${AIDS[presenter]}" -s "$CREDENTIAL" --from-grant "$HELD" --endpoint "$PRESENTER_ENDPOINT" --output "$RUN_DIR/holder-consent-partial.cesr"
PRESENTED_HELD=$(value "$RUN_DIR/latest-holder.jsonl" exchange)
poll accepted_exchange presenter "$PRESENTED_HELD"
k presenter ipex admit --v2 -a presenter -s "$PRESENTED_HELD" --endpoint "$HOLDER_ENDPOINT"
assert_json "$RUN_DIR/latest-presenter.jsonl" admitted true
printf '%s\n' "$PRESENTED_HELD" > "$RUN_DIR/holder-consent-partial-grant.ref"
# The issuer deliberately changes state evidence after the partial admission.
k issuer vc registry opening --registry-name r -s "$CREDENTIAL" --ordinal 1 --output "$RUN_DIR/opening-1.cesr"
k issuer vc registry advance -a issuer -r r -s "$CREDENTIAL"
value "$RUN_DIR/latest-issuer.jsonl" update > "$RUN_DIR/state-event-2.ref"
k issuer vc export --v2 -a issuer -r r -s "$CREDENTIAL" --kels --tels --output "$RUN_DIR/public-2.cesr"
k issuer vc registry publish -a issuer --endpoint "http://127.0.0.1:${PORTS[registrar]}/ingest" --file "$RUN_DIR/public-2.cesr"
for ATTEMPT in {1..40}; do
    k presenter vc registry query -a presenter --endpoint "$OBSERVER_URL" --registry "$REGISTRY" --output "$RUN_DIR/holder-event2-$ATTEMPT.cesr"
    [[ $(value "$RUN_DIR/latest-presenter.jsonl" sn) == 2 ]] && break
    sleep 0.2
done
[[ $(value "$RUN_DIR/latest-presenter.jsonl" sn) == 2 ]]
# Without capability, event 1 cannot open event 2 and --derive cannot succeed.
if k presenter ipex grant --v2 -a presenter -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$PRESENTED_HELD" --refresh --opening "$RUN_DIR/opening-1.cesr" --endpoint "$DOLLY_ENDPOINT" > "$RUN_DIR/wrong-event.log" 2>&1; then exit 1; fi
grep -q 'current registry opening unavailable' "$RUN_DIR/wrong-event.log"
if k presenter ipex grant --v2 -a presenter -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$PRESENTED_HELD" --refresh --derive --endpoint "$DOLLY_ENDPOINT" > "$RUN_DIR/no-custody.log" 2>&1; then exit 1; fi
grep -q 'registry custody is not provisioned' "$RUN_DIR/no-custody.log"

# Explicit issuer-to-presenter per-registry salt transfer. Never print its contents.
k issuer vc export --v2 -a issuer -r r --custody --output "$RUN_DIR/scoped-custody.json"
[[ $(stat -c %a "$RUN_DIR/scoped-custody.json") == 600 ]]
if k presenter vc import --v2 --custody --registry "$REGISTRY" --controller "${AIDS[issuer]}" --discloser "${AIDS[dolly]}" --file "$RUN_DIR/scoped-custody.json" > "$RUN_DIR/wrong-recipient.log" 2>&1; then exit 1; fi
grep -q 'custody operation requires the intended local identifier' "$RUN_DIR/wrong-recipient.log"
if k presenter vc import --v2 --custody --registry "$REGISTRY" --controller "${AIDS[dolly]}" --discloser "${AIDS[presenter]}" --file "$RUN_DIR/scoped-custody.json" > "$RUN_DIR/wrong-authority.log" 2>&1; then exit 1; fi
grep -q 'custody must match the accepted registry controller' "$RUN_DIR/wrong-authority.log"
k presenter vc import --v2 --custody --registry "$REGISTRY" --controller "${AIDS[issuer]}" --discloser "${AIDS[presenter]}" --file "$RUN_DIR/scoped-custody.json"
# Close and reopen the long-running presenter intake as well as each command store.
stop presenter-intake
spawn presenter-intake kli ipex receive --v2 --name "${NAMES[presenter]}" --base "$STORE_BASE" -a presenter --port "${PORTS[presenter]}"
python "$JSON" tcp-ready 127.0.0.1 "${PORTS[presenter]}" 15
k presenter vc registry opening --registry "$REGISTRY" --from-grant "$PRESENTED_HELD" -s "$CREDENTIAL" --ordinal 2 --output "$RUN_DIR/presenter-derived-2.cesr"
if k presenter vc registry opening --registry "$REGISTRY" --from-grant "$PRESENTED_HELD" -s "$REGISTRY" --ordinal 2 --output "$RUN_DIR/wrong-credential.cesr" > "$RUN_DIR/wrong-credential.log" 2>&1; then exit 1; fi
grep -q 'admitted grant does not bind the requested credential' "$RUN_DIR/wrong-credential.log"
[[ ! -e "$RUN_DIR/wrong-credential.cesr" ]]

# Partial onward negotiation, signed by the selected presenter and received by external Dolly.
k dolly ipex apply --v2 -a dolly -r "${AIDS[presenter]}" --plan "@$RUN_DIR/partial-plan.json" --endpoint "$PRESENTER_ENDPOINT"
APPLY=$(value "$RUN_DIR/latest-dolly.jsonl" exchange)
k presenter ipex offer --v2 -a presenter -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$PRESENTED_HELD" \
    --prior "$APPLY" --disclose a/status/ --endpoint "$DOLLY_ENDPOINT"
OFFER=$(value "$RUN_DIR/latest-presenter.jsonl" exchange)
poll accepted_exchange dolly "$OFFER"
k dolly ipex agree --v2 -a dolly -s "$OFFER" --endpoint "$PRESENTER_ENDPOINT"
AGREE=$(value "$RUN_DIR/latest-dolly.jsonl" exchange)
k presenter ipex grant --v2 -a presenter -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$PRESENTED_HELD" \
    --prior "$AGREE" --refresh --derive --disclose a/status/ --endpoint "$DOLLY_ENDPOINT" --output "$RUN_DIR/holder-partial.cesr"
PARTIAL=$(value "$RUN_DIR/latest-presenter.jsonl" exchange)
poll delivered "$PARTIAL"
python "$JSON" assert-hooks "$RUN_DIR/hooks.jsonl" 1 "$CREDENTIAL" "${AIDS[presenter]}"
python "$JSON" first-hook "$RUN_DIR/hooks.jsonl" "$RUN_DIR/first-hook.json"
FIRST_HOOK_HASH=$(python "$JSON" hash "$RUN_DIR/first-hook.json")
k dolly ipex inspect -s "$PARTIAL" > "$RUN_DIR/partial-retained-before.json"
PARTIAL_HASH=$(python "$JSON" hash "$RUN_DIR/partial-retained-before.json")
k dolly ipex admit --v2 -a dolly -s "$PARTIAL" --endpoint "$PRESENTER_ENDPOINT"

# A request for the withheld private leaf cannot be satisfied from this admission.
python "$JSON" plan "$RUN_DIR/withheld-plan.json" "$SCHEMA" withheld
k dolly ipex apply --v2 -a dolly -r "${AIDS[presenter]}" --plan "@$RUN_DIR/withheld-plan.json" --endpoint "$PRESENTER_ENDPOINT"
UNAVAILABLE=$(value "$RUN_DIR/latest-dolly.jsonl" exchange)
if k presenter ipex grant --v2 -a presenter -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$PRESENTED_HELD" --prior "$UNAVAILABLE" --refresh --derive --endpoint "$DOLLY_ENDPOINT" > "$RUN_DIR/unavailable-fuller.jsonl" 2>&1; then
    printf 'Unexpected withheld-field grant from partial admission\n' >&2; exit 1
fi
assert_unavailable_disclosure "$RUN_DIR/unavailable-fuller.jsonl"
python "$JSON" assert-hooks "$RUN_DIR/hooks.jsonl" 1 "$CREDENTIAL" "${AIDS[presenter]}"

# Holder independently acquires event 2 before admitting its later disclosure.
k holder vc registry query -a holder --endpoint "$OBSERVER_URL" --registry "$REGISTRY" --output "$RUN_DIR/holder-current-2.cesr"
assert_json "$RUN_DIR/latest-holder.jsonl" sn 2

# A second negotiated issuer disclosure explicitly supplies the missing blocks.
k holder ipex apply --v2 -a holder -r "${AIDS[issuer]}" --plan "@$RUN_DIR/full-plan.json" --endpoint "$ISSUER_ENDPOINT"
APPLY_ISSUER_FULL=$(value "$RUN_DIR/latest-holder.jsonl" exchange)
k issuer ipex offer --v2 -a issuer -r "${AIDS[holder]}" -s "$CREDENTIAL" --prior "$APPLY_ISSUER_FULL" --endpoint "$HOLDER_ENDPOINT"
OFFER_ISSUER_FULL=$(value "$RUN_DIR/latest-issuer.jsonl" exchange)
poll accepted_exchange holder "$OFFER_ISSUER_FULL"
k holder ipex agree --v2 -a holder -s "$OFFER_ISSUER_FULL" --endpoint "$ISSUER_ENDPOINT"
AGREE_ISSUER_FULL=$(value "$RUN_DIR/latest-holder.jsonl" exchange)
k issuer ipex grant --v2 -a issuer -r "${AIDS[holder]}" -s "$CREDENTIAL" --prior "$AGREE_ISSUER_FULL" --endpoint "$HOLDER_ENDPOINT"
HELD_FULL=$(value "$RUN_DIR/latest-issuer.jsonl" exchange)
[[ $HELD_FULL != "$HELD" ]]
poll accepted_exchange holder "$HELD_FULL"
k holder ipex admit --v2 -a holder -s "$HELD_FULL" --endpoint "$ISSUER_ENDPOINT"
assert_json "$RUN_DIR/latest-holder.jsonl" admitted true

# Fuller material reaches the presenter only through a second holder consent.
k holder ipex grant --v2 -a holder -r "${AIDS[presenter]}" -s "$CREDENTIAL" --from-grant "$HELD_FULL" --endpoint "$PRESENTER_ENDPOINT" --output "$RUN_DIR/holder-consent-full.cesr"
PRESENTED_HELD_FULL=$(value "$RUN_DIR/latest-holder.jsonl" exchange)
poll accepted_exchange presenter "$PRESENTED_HELD_FULL"
k presenter ipex admit --v2 -a presenter -s "$PRESENTED_HELD_FULL" --endpoint "$HOLDER_ENDPOINT"
assert_json "$RUN_DIR/latest-presenter.jsonl" admitted true
printf '%s\n' "$PRESENTED_HELD_FULL" > "$RUN_DIR/holder-consent-full-grant.ref"
# Fuller onward negotiation now uses the explicit second admission.
k dolly ipex apply --v2 -a dolly -r "${AIDS[presenter]}" --plan "@$RUN_DIR/full-plan.json" --endpoint "$PRESENTER_ENDPOINT"
APPLY_FULL=$(value "$RUN_DIR/latest-dolly.jsonl" exchange)
k presenter ipex offer --v2 -a presenter -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$PRESENTED_HELD_FULL" \
    --prior "$APPLY_FULL" --endpoint "$DOLLY_ENDPOINT"
OFFER_FULL=$(value "$RUN_DIR/latest-presenter.jsonl" exchange)
poll accepted_exchange dolly "$OFFER_FULL"
k dolly ipex agree --v2 -a dolly -s "$OFFER_FULL" --endpoint "$PRESENTER_ENDPOINT"
AGREE_FULL=$(value "$RUN_DIR/latest-dolly.jsonl" exchange)
k presenter ipex grant --v2 -a presenter -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$PRESENTED_HELD_FULL" \
    --prior "$AGREE_FULL" --refresh --derive --endpoint "$DOLLY_ENDPOINT" --output "$RUN_DIR/holder-full.cesr"
FULL=$(value "$RUN_DIR/latest-presenter.jsonl" exchange)
[[ $FULL != "$PARTIAL" ]]
poll delivered "$FULL"
python "$JSON" assert-hooks "$RUN_DIR/hooks.jsonl" 2 "$CREDENTIAL" "${AIDS[presenter]}"
k dolly ipex admit --v2 -a dolly -s "$FULL" --endpoint "$PRESENTER_ENDPOINT"
k dolly ipex inspect -s "$PARTIAL" > "$RUN_DIR/partial-retained-after.json"
[[ $(python "$JSON" hash "$RUN_DIR/partial-retained-after.json") == "$PARTIAL_HASH" ]]
python "$JSON" first-hook "$RUN_DIR/hooks.jsonl" "$RUN_DIR/first-hook-after.json"
[[ $(python "$JSON" hash "$RUN_DIR/first-hook-after.json") == "$FIRST_HOOK_HASH" ]]
k presenter vc list --v2 -a presenter > "$RUN_DIR/holder-inventory.jsonl"
[[ $(grep -c '"grant"' "$RUN_DIR/holder-inventory.jsonl") == 2 ]]
printf '%s\n' "$PARTIAL" > "$RUN_DIR/partial-grant.ref"
printf '%s\n' "$FULL" > "$RUN_DIR/full-grant.ref"
if k holder vc registry opening --registry "$REGISTRY" --from-grant "$HELD_FULL" -s "$CREDENTIAL" --ordinal 2 --output "$RUN_DIR/holder-forbidden-opening.cesr" > "$RUN_DIR/holder-no-salt.log" 2>&1; then exit 1; fi
grep -q 'registry custody is not provisioned' "$RUN_DIR/holder-no-salt.log"
[[ ! -e "$RUN_DIR/holder-forbidden-opening.cesr" ]]
python "$JSON" assert-no-secret "$RUN_DIR/scoped-custody.json" "$RUN_DIR/hooks.jsonl" "$RUN_DIR/commands.log"
result
