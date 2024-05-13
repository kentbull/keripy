#!/bin/bash
# Creates three AIDs, larry, moe, and curly.
# Then, creates a multisig AID, threestooges, with larry and moe.
# Later, curly is rotated into the threestooges AID.
# Finally, larry is rotated out of the threestooges AID.

# Pull in colored text
source "${KERI_SCRIPT_DIR}"/demo/basic/script-utils.sh

# create keystores and AIDs for larry, moe, and curly
export LARRY=EKZYoeLcSpoBn7DdD0Rugk3xGy6in8zJvhJpMhZ23ETe
export MOE=EJ__4LOcMfGRU0V65ywo9GgczMkqTZtgjmCKWU06MDQR
export CURLY=EItXS2M_iaQvYRex9swUaCWLETsxFdQbQD0XZmbukKOV

# Witness prefix
export WAN_WITNESS_PREFIX=BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha


# Step 1/5 Create AIDs

# store multisig-stooge.json as a variable
read -r -d '' STOOGE_ICP_CONFIG_JSON << EOM
{
  "transferable": true,
  "wits": ["$WAN_WITNESS_PREFIX"],
  "toad": 1,
  "icount": 1,
  "ncount": 1,
  "isith": "1",
  "nsith": "1"
}
EOM

print_lcyan "Using AID config file:"
print_lcyan "${STOOGE_ICP_CONFIG_JSON}"

# create temporary file to store json
temp_icp_config=$(mktemp)

# write JSON content to the temp file
echo "$STOOGE_ICP_CONFIG_JSON" > "$temp_icp_config"

echo
print_yellow "Individual AID creation with file: ${KERI_DEMO_SCRIPT_DIR}/data/multisig-stooge.json"
# Larry Prefix EKZYoeLcSpoBn7DdD0Rugk3xGy6in8zJvhJpMhZ23ETe
kli init --name larry \
  --salt 0ACDEyMzQ1Njc4OWxtbm9aBc \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --config-dir "${KERI_SCRIPT_DIR}" \
  --config-file demo-witness-oobis
kli incept --name larry --alias larry \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --file "${temp_icp_config}"

# Moe Prefix EJ__4LOcMfGRU0V65ywo9GgczMkqTZtgjmCKWU06MDQR
kli init --name moe \
  --salt 0ACDEyMzQ1Njc4OWdoaWpsaw \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --config-dir "${KERI_SCRIPT_DIR}" \
  --config-file demo-witness-oobis
kli incept --name moe --alias moe \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --file "${temp_icp_config}"

# Curly Prefix EItXS2M_iaQvYRex9swUaCWLETsxFdQbQD0XZmbukKOV
kli init --name curly \
  --salt 0ACDEyMzQ1Njc4OWdoaWpsaw \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --config-dir "${KERI_SCRIPT_DIR}" \
  --config-file demo-witness-oobis
kli incept --name curly --alias curly \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --file "${temp_icp_config}"
echo

rm "$temp_icp_config"


# Step 2/5 Add contacts with OOBIs
echo
print_yellow "Resolve OOBIs"
kli oobi resolve --name larry --oobi-alias moe \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$MOE/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name larry --oobi-alias curly \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$CURLY/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

kli oobi resolve --name moe --oobi-alias larry \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$LARRY/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name moe --oobi-alias curly \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$CURLY/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

kli oobi resolve --name curly --oobi-alias larry \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$LARRY/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name curly --oobi-alias moe \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$MOE/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
echo


# Step 3/5 Create multisig AID
echo
print_yellow "Multisig Inception for alias: threestooges with Larry and Moe"
print_yellow "Multisig Inception with file: ${KERI_DEMO_SCRIPT_DIR}/data/multisig-two-stooges.json"

# store multisig-two-stooges.json as a variable
read -r -d '' MULTISIG_ICP_CONFIG_JSON << EOM
{
  "aids": [
    "$LARRY",
    "$MOE"
  ],
  "transferable": true,
  "wits": ["$WAN_WITNESS_PREFIX"],
  "toad": 1,
  "isith": "2",
  "nsith": "2"
}
EOM

print_lcyan "Using multisig config file:"
print_lcyan "${MULTISIG_ICP_CONFIG_JSON}"

# create temporary file to store json
temp_multisig_config=$(mktemp)

# write JSON content to the temp file
echo "$MULTISIG_ICP_CONFIG_JSON" > "$temp_multisig_config"

# Follow commands run in parallel
print_yellow "Multisig Inception for Larry: ${LARRY}"
kli multisig incept --name larry --alias larry \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --group "threestooges" \
  --file "${KERI_DEMO_SCRIPT_DIR}/data/multisig-two-stooges.json" &
pid=$!
PID_LIST+=" $pid"
sleep 1

echo
print_yellow "Multisig Inception for Moe: ${MOE}"
kli multisig incept --name moe --alias moe \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --group "threestooges" \
  --file "${KERI_DEMO_SCRIPT_DIR}/data/multisig-two-stooges.json" &
pid=$!
PID_LIST+=" $pid"
sleep 1

echo
print_yellow "Multisig Inception - wait"
echo
wait $PID_LIST

rm "$temp_multisig_config"

# Check status for larry
print_yellow "Check multisig status for Larry"
kli status --name larry --alias threestooges --passcode "DoB26Fj4x9LboAFWJra17O"


# Step 4/5 rotate each individual keystore - required prior to performing rotation
echo
print_yellow "Rotate each individual keystore"
kli rotate --name larry --alias larry --passcode "DoB26Fj4x9LboAFWJra17O"
kli rotate --name moe   --alias moe   --passcode "DoB26Fj4x9LboAFWJra17O"
kli rotate --name curly --alias curly --passcode "DoB26Fj4x9LboAFWJra17O"


# Step 5/5 Pull the latest keystate so each participant knows each other participant's key state
echo
print_yellow "Pull key state in from other multisig group participant identifiers"
kli query --name larry --alias larry --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $MOE
kli query --name larry --alias larry --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $CURLY
kli query --name moe   --alias moe   --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $LARRY
kli query --name moe   --alias moe   --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $CURLY
kli query --name curly --alias curly --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $LARRY
kli query --name curly --alias curly --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $MOE
echo


# Step 6/6 Rotate Curly into the threestooges AID
echo
print_yellow "Multisig rotation with alias: threestooges"

PID_LIST=""

print_yellow "Larry rotates - curly in"
kli multisig rotate --name larry --alias "threestooges" \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --isith '["1/2", "1/2"]' \
  --smids $LARRY \
  --smids $MOE \
  --nsith '["1/3", "1/3", "1/3"]' \
  --rmids $LARRY \
  --rmids $MOE \
  --rmids $CURLY &
pid=$!
PID_LIST+=" $pid"
sleep 1

print_yellow "Moe rotates - curly in"
kli multisig rotate --name moe --alias "threestooges" \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --isith '["1/2", "1/2"]' \
  --smids $LARRY \
  --smids $MOE \
  --nsith '["1/3", "1/3", "1/3"]' \
  --rmids $LARRY \
  --rmids $MOE \
  --rmids $CURLY &
pid=$!
PID_LIST+=" $pid"
sleep 1

echo
print_yellow "Multisig rotation ${ALIAS} - wait"
wait $PID_LIST

# Check status for larry
kli status --name larry --alias threestooges --passcode "DoB26Fj4x9LboAFWJra17O"
# Check status for moe
kli status --name moe   --alias threestooges --passcode "DoB26Fj4x9LboAFWJra17O"
# Check status for curly
kli status --name curly --alias threestooges --passcode "DoB26Fj4x9LboAFWJra17O"

print_green "Multisig rotation - complete"