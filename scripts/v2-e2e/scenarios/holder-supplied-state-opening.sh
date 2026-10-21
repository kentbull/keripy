#!/usr/bin/env bash
# S3: full content plus a supplied event opening; no holder derivation custody.
set -Eeuo pipefail
source "$(dirname -- "$0")/common.sh"
AUTHORIZATION_PROFILE="Issuer supplies a bearer CESR opening scoped to one accepted event and credential; no recipient envelope or delegation protocol; holder retains no derivation salt"
prepare holder-supplied-state-opening

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

# Exactly one full grant is admitted by the holder. No holder custody import.
k issuer ipex grant --v2 -a issuer -r "${AIDS[holder]}" -s "$CREDENTIAL" \
    --endpoint "$HOLDER_ENDPOINT" --output "$RUN_DIR/issuer-full.cesr"
HELD=$(value "$RUN_DIR/latest-issuer.jsonl" exchange)
poll accepted_exchange holder "$HELD"
k holder ipex admit --v2 -a holder -s "$HELD" --endpoint "$ISSUER_ENDPOINT"
assert_json "$RUN_DIR/latest-holder.jsonl" admitted true
printf '%s\n' "$HELD" > "$RUN_DIR/held-grant.ref"
# A separate real credential supplies a cryptographically valid wrong proof.
k issuer vc registry incept --v2 -a issuer -r other --with-custody
k issuer vc create --v2 -a issuer -r other --recipient "${AIDS[holder]}" --data "@$RUN_DIR/attributes.json"
OTHER=$(value "$RUN_DIR/latest-issuer.jsonl" credential)
k issuer vc registry opening --registry-name other -s "$OTHER" --ordinal 1 --output "$RUN_DIR/wrong-credential-opening.cesr"
# Advance the actual witnessed registry after the holder received event 1.
k issuer vc registry opening --registry-name r -s "$CREDENTIAL" --ordinal 1 --output "$RUN_DIR/opening-1.cesr"
k issuer vc registry advance -a issuer -r r -s "$CREDENTIAL"
value "$RUN_DIR/latest-issuer.jsonl" update > "$RUN_DIR/state-event-2.ref"
k issuer vc registry opening --registry-name r -s "$CREDENTIAL" --ordinal 2 --output "$RUN_DIR/opening-2.cesr"
k issuer vc export --v2 -a issuer -r r -s "$CREDENTIAL" --kels --tels --output "$RUN_DIR/public-2.cesr"
k issuer vc registry publish -a issuer --endpoint "http://127.0.0.1:${PORTS[registrar]}/ingest" --file "$RUN_DIR/public-2.cesr"
for ATTEMPT in {1..40}; do
    k holder vc registry query -a holder --endpoint "$OBSERVER_URL" --registry "$REGISTRY" --output "$RUN_DIR/holder-event2-$ATTEMPT.cesr"
    [[ $(value "$RUN_DIR/latest-holder.jsonl" sn) == 2 ]] && break
    sleep 0.2
done
[[ $(value "$RUN_DIR/latest-holder.jsonl" sn) == 2 ]]

# Full attributes do not supply a new opening. Event 1 cannot open event 2.
if k holder ipex grant --v2 -a holder -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$HELD" --refresh --endpoint "$DOLLY_ENDPOINT" > "$RUN_DIR/missing-opening.log" 2>&1; then exit 1; fi
grep -q 'current registry opening unavailable' "$RUN_DIR/missing-opening.log"
if k holder ipex grant --v2 -a holder -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$HELD" --refresh --opening "$RUN_DIR/opening-1.cesr" --endpoint "$DOLLY_ENDPOINT" > "$RUN_DIR/wrong-event.log" 2>&1; then exit 1; fi
grep -q 'current registry opening unavailable' "$RUN_DIR/wrong-event.log"
if k holder ipex grant --v2 -a holder -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$HELD" --refresh --opening "$RUN_DIR/wrong-credential-opening.cesr" --endpoint "$DOLLY_ENDPOINT" > "$RUN_DIR/wrong-credential.log" 2>&1; then exit 1; fi
grep -q 'current registry opening unavailable' "$RUN_DIR/wrong-credential.log"
[[ ! -s "$RUN_DIR/hooks.jsonl" ]]

# The operator hands only the event-specific bearer proof to the holder.
cp "$RUN_DIR/opening-2.cesr" "$RUN_DIR/holder-opening.cesr"
stop issuer-intake

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
    --prior "$AGREE" --refresh --opening "$RUN_DIR/holder-opening.cesr" --disclose a/status/ --endpoint "$DOLLY_ENDPOINT" --output "$RUN_DIR/holder-partial.cesr"
PARTIAL=$(value "$RUN_DIR/latest-holder.jsonl" exchange)
poll delivered "$PARTIAL"
python "$JSON" assert-hooks "$RUN_DIR/hooks.jsonl" 1 "$CREDENTIAL" "${AIDS[holder]}"
python "$JSON" first-hook "$RUN_DIR/hooks.jsonl" "$RUN_DIR/first-hook.json"
FIRST_HOOK_HASH=$(python "$JSON" hash "$RUN_DIR/first-hook.json")
k dolly ipex inspect -s "$PARTIAL" > "$RUN_DIR/partial-retained-before.json"
PARTIAL_HASH=$(python "$JSON" hash "$RUN_DIR/partial-retained-before.json")
k dolly ipex admit --v2 -a dolly -s "$PARTIAL" --endpoint "$HOLDER_ENDPOINT"

# Fuller onward negotiation draws from the SAME full admission after reopening.
k dolly ipex apply --v2 -a dolly -r "${AIDS[holder]}" --plan "@$RUN_DIR/full-plan.json" --endpoint "$HOLDER_ENDPOINT"
APPLY_FULL=$(value "$RUN_DIR/latest-dolly.jsonl" exchange)
k holder ipex offer --v2 -a holder -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$HELD" \
    --prior "$APPLY_FULL" --endpoint "$DOLLY_ENDPOINT"
OFFER_FULL=$(value "$RUN_DIR/latest-holder.jsonl" exchange)
poll accepted_exchange dolly "$OFFER_FULL"
k dolly ipex agree --v2 -a dolly -s "$OFFER_FULL" --endpoint "$HOLDER_ENDPOINT"
AGREE_FULL=$(value "$RUN_DIR/latest-dolly.jsonl" exchange)
k holder ipex grant --v2 -a holder -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$HELD" \
    --prior "$AGREE_FULL" --refresh --opening "$RUN_DIR/holder-opening.cesr" --endpoint "$DOLLY_ENDPOINT" --output "$RUN_DIR/holder-full.cesr"
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
[[ $(grep -c '"grant"' "$RUN_DIR/holder-inventory.jsonl") == 1 ]]
printf '%s\n' "$PARTIAL" > "$RUN_DIR/partial-grant.ref"
printf '%s\n' "$FULL" > "$RUN_DIR/full-grant.ref"
# A bearer opening for event 2 cannot create evidence for later genuine event 3.
k issuer vc registry advance -a issuer -r r -s "$CREDENTIAL"
value "$RUN_DIR/latest-issuer.jsonl" update > "$RUN_DIR/state-event-3.ref"
k issuer vc export --v2 -a issuer -r r -s "$CREDENTIAL" --kels --tels --output "$RUN_DIR/public-3.cesr"
k issuer vc registry publish -a issuer --endpoint "http://127.0.0.1:${PORTS[registrar]}/ingest" --file "$RUN_DIR/public-3.cesr"
for ATTEMPT in {1..40}; do
    k holder vc registry query -a holder --endpoint "$OBSERVER_URL" --registry "$REGISTRY" --output "$RUN_DIR/holder-event3-$ATTEMPT.cesr"
    [[ $(value "$RUN_DIR/latest-holder.jsonl" sn) == 3 ]] && break
    sleep 0.2
done
[[ $(value "$RUN_DIR/latest-holder.jsonl" sn) == 3 ]]
if k holder ipex grant --v2 -a holder -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$HELD" --refresh --opening "$RUN_DIR/holder-opening.cesr" --endpoint "$DOLLY_ENDPOINT" > "$RUN_DIR/no-future-opening.log" 2>&1; then exit 1; fi
grep -q 'current registry opening unavailable' "$RUN_DIR/no-future-opening.log"
if k holder vc registry opening --registry "$REGISTRY" --from-grant "$HELD" -s "$CREDENTIAL" --ordinal 3 --output "$RUN_DIR/unauthorized-derived.cesr" > "$RUN_DIR/no-custody.log" 2>&1; then exit 1; fi
grep -q 'registry custody is not provisioned' "$RUN_DIR/no-custody.log"
[[ ! -e "$RUN_DIR/unauthorized-derived.cesr" ]]
python "$JSON" assert-hooks "$RUN_DIR/hooks.jsonl" 2 "$CREDENTIAL" "${AIDS[holder]}"
result
