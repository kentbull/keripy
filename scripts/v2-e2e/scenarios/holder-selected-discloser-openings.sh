#!/usr/bin/env bash
# S5: holder-consented third-party material transfer plus event-specific proofs.
set -Eeuo pipefail
source "$(dirname -- "$0")/common.sh"
AUTHORIZATION_PROFILE="Holder selects distinct presenter through signed full grant and presenter admission; issuer-consistent designated discloser; issuer supplies bearer event proofs via operator file handoff; no delegation protocol or salt transfer"
DISCLOSER_ROLE=presenter
prepare holder-selected-discloser-openings

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

# Exactly one full grant is admitted by the holder. No holder custody import.
k issuer ipex grant --v2 -a issuer -r "${AIDS[holder]}" -s "$CREDENTIAL" \
    --endpoint "$HOLDER_ENDPOINT" --output "$RUN_DIR/issuer-full.cesr"
HELD=$(value "$RUN_DIR/latest-issuer.jsonl" exchange)
poll accepted_exchange holder "$HELD"
k holder ipex admit --v2 -a holder -s "$HELD" --endpoint "$ISSUER_ENDPOINT"
assert_json "$RUN_DIR/latest-holder.jsonl" admitted true
printf '%s\n' "$HELD" > "$RUN_DIR/held-grant.ref"
# Holder consent is a real signed grant addressed to the separate presenter.
PRESENTER_ENDPOINT="http://127.0.0.1:${PORTS[presenter]}/ingest"
# The independent presenter acquires public issuer/TEL dependencies itself.
k presenter vc registry query -a presenter --endpoint "$OBSERVER_URL" --registry "$REGISTRY" --output "$RUN_DIR/presenter-public.cesr"
k holder ipex grant --v2 -a holder -r "${AIDS[presenter]}" -s "$CREDENTIAL" --from-grant "$HELD" --endpoint "$PRESENTER_ENDPOINT" --output "$RUN_DIR/holder-consent.cesr"
PRESENTED_HELD=$(value "$RUN_DIR/latest-holder.jsonl" exchange)
poll accepted_exchange presenter "$PRESENTED_HELD"
k presenter ipex admit --v2 -a presenter -s "$PRESENTED_HELD" --endpoint "$HOLDER_ENDPOINT"
assert_json "$RUN_DIR/latest-presenter.jsonl" admitted true
printf '%s\n' "$PRESENTED_HELD" > "$RUN_DIR/holder-consent-grant.ref"
cat "$RUN_DIR/public.cesr" "$RUN_DIR/holder-consent.cesr" > "$RUN_DIR/wrong-recipient-input.cesr"
# A different local recipient cannot admit the holder's addressed grant.
if k dolly ipex admit --v2 -a dolly -s "$PRESENTED_HELD" --input "$RUN_DIR/wrong-recipient-input.cesr" > "$RUN_DIR/wrong-material-recipient.log" 2>&1; then exit 1; fi
grep -q 'sender does not match prior exchange receiver' "$RUN_DIR/wrong-material-recipient.log"
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
    k presenter vc registry query -a presenter --endpoint "$OBSERVER_URL" --registry "$REGISTRY" --output "$RUN_DIR/holder-event2-$ATTEMPT.cesr"
    [[ $(value "$RUN_DIR/latest-presenter.jsonl" sn) == 2 ]] && break
    sleep 0.2
done
[[ $(value "$RUN_DIR/latest-presenter.jsonl" sn) == 2 ]]

# Full attributes do not supply a new opening. Event 1 cannot open event 2.
if k presenter ipex grant --v2 -a presenter -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$PRESENTED_HELD" --refresh --endpoint "$DOLLY_ENDPOINT" > "$RUN_DIR/missing-opening.log" 2>&1; then exit 1; fi
grep -q 'current registry opening unavailable' "$RUN_DIR/missing-opening.log"
if k presenter ipex grant --v2 -a presenter -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$PRESENTED_HELD" --refresh --opening "$RUN_DIR/opening-1.cesr" --endpoint "$DOLLY_ENDPOINT" > "$RUN_DIR/wrong-event.log" 2>&1; then exit 1; fi
grep -q 'current registry opening unavailable' "$RUN_DIR/wrong-event.log"
if k presenter ipex grant --v2 -a presenter -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$PRESENTED_HELD" --refresh --opening "$RUN_DIR/wrong-credential-opening.cesr" --endpoint "$DOLLY_ENDPOINT" > "$RUN_DIR/wrong-credential.log" 2>&1; then exit 1; fi
grep -q 'current registry opening unavailable' "$RUN_DIR/wrong-credential.log"
[[ ! -s "$RUN_DIR/hooks.jsonl" ]]

# The operator hands only the event-specific bearer proof to the selected presenter.
cp "$RUN_DIR/opening-2.cesr" "$RUN_DIR/presenter-opening.cesr"
stop issuer-intake
stop holder-intake

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
    --prior "$AGREE" --refresh --opening "$RUN_DIR/presenter-opening.cesr" --disclose a/status/ --endpoint "$DOLLY_ENDPOINT" --output "$RUN_DIR/holder-partial.cesr"
PARTIAL=$(value "$RUN_DIR/latest-presenter.jsonl" exchange)
poll delivered "$PARTIAL"
python "$JSON" assert-hooks "$RUN_DIR/hooks.jsonl" 1 "$CREDENTIAL" "${AIDS[presenter]}"
python "$JSON" first-hook "$RUN_DIR/hooks.jsonl" "$RUN_DIR/first-hook.json"
FIRST_HOOK_HASH=$(python "$JSON" hash "$RUN_DIR/first-hook.json")
k dolly ipex inspect -s "$PARTIAL" > "$RUN_DIR/partial-retained-before.json"
PARTIAL_HASH=$(python "$JSON" hash "$RUN_DIR/partial-retained-before.json")
k dolly ipex admit --v2 -a dolly -s "$PARTIAL" --endpoint "$PRESENTER_ENDPOINT"

# Fuller onward negotiation draws from the SAME full admission after reopening.
k dolly ipex apply --v2 -a dolly -r "${AIDS[presenter]}" --plan "@$RUN_DIR/full-plan.json" --endpoint "$PRESENTER_ENDPOINT"
APPLY_FULL=$(value "$RUN_DIR/latest-dolly.jsonl" exchange)
k presenter ipex offer --v2 -a presenter -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$PRESENTED_HELD" \
    --prior "$APPLY_FULL" --endpoint "$DOLLY_ENDPOINT"
OFFER_FULL=$(value "$RUN_DIR/latest-presenter.jsonl" exchange)
poll accepted_exchange dolly "$OFFER_FULL"
k dolly ipex agree --v2 -a dolly -s "$OFFER_FULL" --endpoint "$PRESENTER_ENDPOINT"
AGREE_FULL=$(value "$RUN_DIR/latest-dolly.jsonl" exchange)
k presenter ipex grant --v2 -a presenter -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$PRESENTED_HELD" \
    --prior "$AGREE_FULL" --refresh --opening "$RUN_DIR/presenter-opening.cesr" --endpoint "$DOLLY_ENDPOINT" --output "$RUN_DIR/holder-full.cesr"
FULL=$(value "$RUN_DIR/latest-presenter.jsonl" exchange)
[[ $FULL != "$PARTIAL" ]]
poll delivered "$FULL"
python "$JSON" assert-hooks "$RUN_DIR/hooks.jsonl" 2 "$CREDENTIAL" "${AIDS[presenter]}"
k dolly ipex admit --v2 -a dolly -s "$FULL" --endpoint "$PRESENTER_ENDPOINT"
k dolly ipex inspect -s "$PARTIAL" > "$RUN_DIR/partial-retained-after.json"
[[ $(python "$JSON" hash "$RUN_DIR/partial-retained-after.json") == "$PARTIAL_HASH" ]]
python "$JSON" first-hook "$RUN_DIR/hooks.jsonl" "$RUN_DIR/first-hook-after.json"
[[ $(python "$JSON" hash "$RUN_DIR/first-hook-after.json") == "$FIRST_HOOK_HASH" ]]
k presenter vc list --v2 -a presenter > "$RUN_DIR/presenter-inventory.jsonl"
[[ $(grep -c '"grant"' "$RUN_DIR/presenter-inventory.jsonl") == 1 ]]
printf '%s\n' "$PARTIAL" > "$RUN_DIR/partial-grant.ref"
printf '%s\n' "$FULL" > "$RUN_DIR/full-grant.ref"
# A bearer opening for event 2 cannot create evidence for later genuine event 3.
k issuer vc registry advance -a issuer -r r -s "$CREDENTIAL"
value "$RUN_DIR/latest-issuer.jsonl" update > "$RUN_DIR/state-event-3.ref"
k issuer vc export --v2 -a issuer -r r -s "$CREDENTIAL" --kels --tels --output "$RUN_DIR/public-3.cesr"
k issuer vc registry publish -a issuer --endpoint "http://127.0.0.1:${PORTS[registrar]}/ingest" --file "$RUN_DIR/public-3.cesr"
for ATTEMPT in {1..40}; do
    k presenter vc registry query -a presenter --endpoint "$OBSERVER_URL" --registry "$REGISTRY" --output "$RUN_DIR/holder-event3-$ATTEMPT.cesr"
    [[ $(value "$RUN_DIR/latest-presenter.jsonl" sn) == 3 ]] && break
    sleep 0.2
done
[[ $(value "$RUN_DIR/latest-presenter.jsonl" sn) == 3 ]]
if k presenter ipex grant --v2 -a presenter -r "${AIDS[dolly]}" -s "$CREDENTIAL" --from-grant "$PRESENTED_HELD" --refresh --opening "$RUN_DIR/presenter-opening.cesr" --endpoint "$DOLLY_ENDPOINT" > "$RUN_DIR/no-future-opening.log" 2>&1; then exit 1; fi
grep -q 'current registry opening unavailable' "$RUN_DIR/no-future-opening.log"
if k presenter vc registry opening --registry "$REGISTRY" --from-grant "$PRESENTED_HELD" -s "$CREDENTIAL" --ordinal 3 --output "$RUN_DIR/unauthorized-derived.cesr" > "$RUN_DIR/no-custody.log" 2>&1; then exit 1; fi
grep -q 'registry custody is not provisioned' "$RUN_DIR/no-custody.log"
[[ ! -e "$RUN_DIR/unauthorized-derived.cesr" ]]
python "$JSON" assert-hooks "$RUN_DIR/hooks.jsonl" 2 "$CREDENTIAL" "${AIDS[presenter]}"
result
