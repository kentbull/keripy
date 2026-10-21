#!/usr/bin/env bash
# S2: partial admission cannot become full until a later explicit full admission.
set -Eeuo pipefail
source "$(dirname -- "$0")/common.sh"
prepare holder-partial-then-onward

# The only credential issuance. Blinded issuer custody is explicitly provisioned.
k issuer vc registry incept --v2 -a issuer -r r --with-custody
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

# Partial onward negotiation, signed by the holder and received by external Dolly.
k dolly ipex apply --v2 -a dolly -r "${AIDS[holder]}" --plan "@$RUN_DIR/partial-plan.json" --endpoint "$HOLDER_ENDPOINT"
APPLY=$(value "$RUN_DIR/latest-dolly.jsonl" exchange)
k holder ipex offer --v2 -a holder -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$HELD" \
    --prior "$APPLY" --disclose a/status/ --endpoint "$DOLLY_ENDPOINT"
OFFER=$(value "$RUN_DIR/latest-holder.jsonl" exchange)
poll accepted_exchange dolly "$OFFER"
k dolly ipex agree --v2 -a dolly -s "$OFFER" --endpoint "$HOLDER_ENDPOINT"
AGREE=$(value "$RUN_DIR/latest-dolly.jsonl" exchange)
k holder ipex grant --v2 -a holder -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$HELD" \
    --prior "$AGREE" --disclose a/status/ --endpoint "$DOLLY_ENDPOINT" --output "$RUN_DIR/holder-partial.cesr"
PARTIAL=$(value "$RUN_DIR/latest-holder.jsonl" exchange)
poll delivered "$PARTIAL"
python "$JSON" assert-hooks "$RUN_DIR/hooks.jsonl" 1 "$CREDENTIAL" "${AIDS[holder]}"
python "$JSON" first-hook "$RUN_DIR/hooks.jsonl" "$RUN_DIR/first-hook.json"
FIRST_HOOK_HASH=$(python "$JSON" hash "$RUN_DIR/first-hook.json")
k dolly ipex inspect -s "$PARTIAL" > "$RUN_DIR/partial-retained-before.json"
PARTIAL_HASH=$(python "$JSON" hash "$RUN_DIR/partial-retained-before.json")
k dolly ipex admit --v2 -a dolly -s "$PARTIAL" --endpoint "$HOLDER_ENDPOINT"

# A request for the withheld private leaf cannot be satisfied from this admission.
python "$JSON" plan "$RUN_DIR/withheld-plan.json" "$SCHEMA" withheld
k dolly ipex apply --v2 -a dolly -r "${AIDS[holder]}" --plan "@$RUN_DIR/withheld-plan.json" --endpoint "$HOLDER_ENDPOINT"
UNAVAILABLE=$(value "$RUN_DIR/latest-dolly.jsonl" exchange)
if k holder ipex grant --v2 -a holder -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$HELD" --prior "$UNAVAILABLE" --endpoint "$DOLLY_ENDPOINT" > "$RUN_DIR/unavailable-fuller.jsonl" 2>&1; then
    printf 'Unexpected withheld-field grant from partial admission\n' >&2; exit 1
fi
assert_unavailable_disclosure "$RUN_DIR/unavailable-fuller.jsonl"
python "$JSON" assert-hooks "$RUN_DIR/hooks.jsonl" 1 "$CREDENTIAL" "${AIDS[holder]}"

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

# Fuller onward negotiation now uses the explicit second admission.
k dolly ipex apply --v2 -a dolly -r "${AIDS[holder]}" --plan "@$RUN_DIR/full-plan.json" --endpoint "$HOLDER_ENDPOINT"
APPLY_FULL=$(value "$RUN_DIR/latest-dolly.jsonl" exchange)
k holder ipex offer --v2 -a holder -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$HELD_FULL" \
    --prior "$APPLY_FULL" --endpoint "$DOLLY_ENDPOINT"
OFFER_FULL=$(value "$RUN_DIR/latest-holder.jsonl" exchange)
poll accepted_exchange dolly "$OFFER_FULL"
k dolly ipex agree --v2 -a dolly -s "$OFFER_FULL" --endpoint "$HOLDER_ENDPOINT"
AGREE_FULL=$(value "$RUN_DIR/latest-dolly.jsonl" exchange)
k holder ipex grant --v2 -a holder -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$HELD_FULL" \
    --prior "$AGREE_FULL" --endpoint "$DOLLY_ENDPOINT" --output "$RUN_DIR/holder-full.cesr"
FULL=$(value "$RUN_DIR/latest-holder.jsonl" exchange)
[[ $FULL != "$PARTIAL" ]]
poll delivered "$FULL"
python "$JSON" assert-hooks "$RUN_DIR/hooks.jsonl" 2 "$CREDENTIAL" "${AIDS[holder]}"
k dolly ipex admit --v2 -a dolly -s "$FULL" --endpoint "$HOLDER_ENDPOINT"
k dolly ipex inspect -s "$PARTIAL" > "$RUN_DIR/partial-retained-after.json"
[[ $(python "$JSON" hash "$RUN_DIR/partial-retained-after.json") == "$PARTIAL_HASH" ]]
python "$JSON" first-hook "$RUN_DIR/hooks.jsonl" "$RUN_DIR/first-hook-after.json"
[[ $(python "$JSON" hash "$RUN_DIR/first-hook-after.json") == "$FIRST_HOOK_HASH" ]]
k holder vc list --v2 -a holder > "$RUN_DIR/holder-inventory.jsonl"
[[ $(grep -c '"grant"' "$RUN_DIR/holder-inventory.jsonl") == 2 ]]
printf '%s\n' "$PARTIAL" > "$RUN_DIR/partial-grant.ref"
printf '%s\n' "$FULL" > "$RUN_DIR/full-grant.ref"
result
