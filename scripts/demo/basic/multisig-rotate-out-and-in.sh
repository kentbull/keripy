#!/bin/bash
# multisig-rotate-out-and-in.sh
# This file is self contained except for the keystore initialization config file.
# The inception configuration and multisig configuration files are included in the script
# as here docs.
#
# Required services:
# - KERI witness demo nodes running.
#     Use the `kli witness demo` command
# - vLEI schema server running.
#     Use the `vLEI-server -s ./schema/acdc -c ./samples/acdc/ -o ./samples/oobis/` command.


# This script creates four AIDs, larry, moe, curly, and alfred.
# Next, creates a multisig AID, threestooges, with larry and moe.
# curly is then rotated into the threestooges AID.
# larry is rotated out of the threestooges AID.
# alfred is rotated into the threestooges AID.


# Pull in colored text
source "${KERI_SCRIPT_DIR}"/demo/basic/script-utils.sh

# create keystores and AIDs for larry, moe, and curly
export LARRY=EKZYoeLcSpoBn7DdD0Rugk3xGy6in8zJvhJpMhZ23ETe
export MOE=EJ__4LOcMfGRU0V65ywo9GgczMkqTZtgjmCKWU06MDQR
export CURLY=EItXS2M_iaQvYRex9swUaCWLETsxFdQbQD0XZmbukKOV
export ALFRED=ECl8nwhRYub9Se_Caes40ex0vJXi9v84CaydEalEZgH3

# Witness prefix
export WAN_WITNESS_PREFIX=BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

echo
print_yellow "Step 1/9 Create AIDs larry, moe, curly, and alfred"
echo

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

print_lcyan "Using temporary AID config file heredoc:"
print_lcyan "${STOOGE_ICP_CONFIG_JSON}"

# create temporary file to store json
temp_icp_config=$(mktemp)

# write JSON content to the temp file
echo "$STOOGE_ICP_CONFIG_JSON" > "$temp_icp_config"

echo
print_yellow "Individual AID creation with temp config file."
print_green "larry: ${LARRY}"
# larry Prefix EKZYoeLcSpoBn7DdD0Rugk3xGy6in8zJvhJpMhZ23ETe
kli init --name larry \
  --salt 0ACDEyMzQ1Njc4OWxtbm9aBc \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --config-dir "${KERI_SCRIPT_DIR}" \
  --config-file demo-witness-oobis
kli incept --name larry --alias larry \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --file "${temp_icp_config}"

# moe Prefix EJ__4LOcMfGRU0V65ywo9GgczMkqTZtgjmCKWU06MDQR
print_green "moe: ${MOE}"
kli init --name moe \
  --salt 0ACDEyMzQ1Njc4OWdoaWpsaw \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --config-dir "${KERI_SCRIPT_DIR}" \
  --config-file demo-witness-oobis
kli incept --name moe --alias moe \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --file "${temp_icp_config}"

# curly Prefix EItXS2M_iaQvYRex9swUaCWLETsxFdQbQD0XZmbukKOV
print_green "curly: ${CURLY}"
kli init --name curly \
  --salt 0ACDEyMzQ1Njc4OWdoaWpsaw \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --config-dir "${KERI_SCRIPT_DIR}" \
  --config-file demo-witness-oobis
kli incept --name curly --alias curly \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --file "${temp_icp_config}"
echo

# alfred Prefix EItXS2M_iaQvYRex9swUaCWLETsxFdQbQD0XZmbukKOV
print_green "alfred: ${ALFRED}"
kli init --name alfred \
  --salt 0ACDEyMzQ1Njc4OWdoaWpsaw \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --config-dir "${KERI_SCRIPT_DIR}" \
  --config-file demo-witness-oobis
kli incept --name alfred --alias alfred \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --file "${temp_icp_config}"
echo

rm "$temp_icp_config"

echo
print_yellow "Step 2/9 Add contacts with OOBIs using 'wan' as the witness"
echo

echo
print_yellow "Resolve OOBIs between all participants (8 total)"
print_yellow "larry -> {moe, curly, alfred}"
kli oobi resolve --name larry --oobi-alias moe \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$MOE/witness/$WAN_WITNESS_PREFIX
kli oobi resolve --name larry --oobi-alias curly \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$CURLY/witness/$WAN_WITNESS_PREFIX
kli oobi resolve --name larry --oobi-alias alfred \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$ALFRED/witness/$WAN_WITNESS_PREFIX

print_yellow "moe -> {larry, curly, alfred}"
kli oobi resolve --name moe --oobi-alias larry \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$LARRY/witness/$WAN_WITNESS_PREFIX
kli oobi resolve --name moe --oobi-alias curly \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$CURLY/witness/$WAN_WITNESS_PREFIX
kli oobi resolve --name moe --oobi-alias alfred \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$ALFRED/witness/$WAN_WITNESS_PREFIX

print_yellow "curly -> {larry, moe, alfred}"
kli oobi resolve --name curly --oobi-alias larry \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$LARRY/witness/$WAN_WITNESS_PREFIX
kli oobi resolve --name curly --oobi-alias moe \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$MOE/witness/$WAN_WITNESS_PREFIX
kli oobi resolve --name curly --oobi-alias alfred \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$ALFRED/witness/$WAN_WITNESS_PREFIX

print_yellow "alfred -> {larry, moe, curly}"
kli oobi resolve --name alfred --oobi-alias larry \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$LARRY/witness/$WAN_WITNESS_PREFIX
kli oobi resolve --name alfred --oobi-alias moe \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$MOE/witness/$WAN_WITNESS_PREFIX
kli oobi resolve --name alfred --oobi-alias curly \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$CURLY/witness/$WAN_WITNESS_PREFIX

echo


echo
print_yellow "Step 3/9 Create multisig AID with larry and moe as participants"
echo

echo
print_yellow "Multisig Inception for alias: threestooges with larry and moe"

# store multisig-two-stooges.json as a variable
print_yellow "Multisig Inception temp config file."
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

print_lcyan "Using temporary multisig config file as heredoc:"
print_lcyan "${MULTISIG_ICP_CONFIG_JSON}"

# create temporary file to store json
temp_multisig_config=$(mktemp)

# write JSON content to the temp file
echo "$MULTISIG_ICP_CONFIG_JSON" > "$temp_multisig_config"

# Follow commands run in parallel
print_yellow "Multisig Inception from larry: ${LARRY}"
kli multisig incept --name larry --alias larry \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --group "threestooges" \
  --file "${temp_multisig_config}" &
pid=$!
PID_LIST+=" $pid"

echo


kli multisig join --name moe  --passcode "DoB26Fj4x9LboAFWJra17O" --group threestooges --auto &
pid=$!
PID_LIST+=" $pid"

# Uncomment when running by hand (and comment out the above join command):
#print_lcyan "Run: "
#print_green "  kli multisig join --name moe   --passcode \"DoB26Fj4x9LboAFWJra17O\" --group threestooges"
#print_lcyan "in a terminal from 'keripy/scripts/demo' that has run 'source ./demo-scripts.sh'"
#read -r -p "Press enter to continue after moe joins the inception"

echo
print_yellow "Multisig Inception {larry, moe} - wait for signatures"
echo
wait $PID_LIST

rm "$temp_multisig_config"

# Check status for larry
echo
print_yellow "Check multisig status for larry"
kli status --name larry --alias threestooges --passcode "DoB26Fj4x9LboAFWJra17O"
print_yellow "Check multisig status for moe"
kli status --name moe   --alias threestooges --passcode "DoB26Fj4x9LboAFWJra17O"
echo


echo
print_yellow "Step 4/9 rotate each individual keystore and update keystate - required prior to performing rotation"
echo

function rotate_individual_aids() {
  echo
  print_yellow "Rotate each individual keystore"
  kli rotate --name larry  --alias larry  --passcode "DoB26Fj4x9LboAFWJra17O"
  kli rotate --name moe    --alias moe    --passcode "DoB26Fj4x9LboAFWJra17O"
  kli rotate --name curly  --alias curly  --passcode "DoB26Fj4x9LboAFWJra17O"
  kli rotate --name alfred --alias alfred --passcode "DoB26Fj4x9LboAFWJra17O"
  echo
}

function query_keystate_all_participants() {
  echo
  print_yellow "Pull key state in from other multisig group participant identifiers"
  print_yellow "Key State Query: larry -> {moe, curly, alfred}"
  kli query --name larry --alias larry --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $MOE
  kli query --name larry --alias larry --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $CURLY
  kli query --name larry --alias larry --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $ALFRED

  print_yellow "Key State Query: moe -> {larry, curly, alfred}"
  kli query --name moe   --alias moe   --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $LARRY
  kli query --name moe   --alias moe   --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $CURLY
  kli query --name moe   --alias moe   --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $ALFRED

  print_yellow "Key State Query: curly -> {larry, moe, alfred}"
  kli query --name curly --alias curly --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $LARRY
  kli query --name curly --alias curly --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $MOE
  kli query --name curly --alias curly --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $ALFRED

  print_yellow "Key State Query: alfred -> {larry, moe, curly}"
  kli query --name alfred --alias alfred --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $LARRY
  kli query --name alfred --alias alfred --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $MOE
  kli query --name alfred --alias alfred --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $CURLY
  echo
}

rotate_individual_aids
query_keystate_all_participants

echo
print_yellow "Step 5/9 Rotate curly into the threestooges AID"
echo

MULTISIG_AID=EGRRbB0Heh3rbyfCnf7vdbYWbKwWASZboMrMtAnGkDDA


print_yellow "Multisig rotation with alias: threestooges"

PID_LIST=""

print_yellow "larry proposes rotation - bring curly in"
kli multisig rotate --name larry --alias "threestooges" \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --isith '["1/3", "1/3", "1/3"]' \
  --smids $LARRY \
  --smids $MOE \
  --smids $CURLY \
  --nsith '["1/3", "1/3", "1/3"]' \
  --rmids $LARRY \
  --rmids $MOE \
  --rmids $CURLY &
pid=$!
PID_LIST+=" $pid"
sleep 1

kli multisig join --name moe  --passcode "DoB26Fj4x9LboAFWJra17O" --group threestooges --auto &
pid=$!
PID_LIST+=" $pid"

# Tell curly about the new multisig AID with OOBI resolve
print_yellow "Resolve threestooges multisig OOBI for curly"
kli oobi resolve --name curly --oobi-alias threestooges \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$MULTISIG_AID/witness/$WAN_WITNESS_PREFIX
echo

kli multisig join --name curly --passcode "DoB26Fj4x9LboAFWJra17O" --group threestooges --auto &
pid=$!
PID_LIST+=" $pid"

# Uncomment when running by hand (and comment out the above join commands):
#print_lcyan "Run: "
#print_green "  kli multisig join --name moe   --passcode \"DoB26Fj4x9LboAFWJra17O\" --group threestooges"
#print_lcyan "and: "
#print_green "  kli multisig join --name curly --passcode \"DoB26Fj4x9LboAFWJra17O\" --group threestooges"
#print_lcyan "in a terminal from 'keripy/scripts/demo' that has run 'source ./demo-scripts.sh'"
#print_lcyan "and then delete any non-rotation notifications."
#print_lcyan "Then join the multisig rotation proposed by larry"
#read -r -p "Press enter to continue after moe and curly join"

echo
print_yellow "Multisig rotation threestooges - wait for signatures"
wait $PID_LIST


# Check status of multisig AIDs
# Check status for larry
kli status --name larry --alias threestooges --passcode "DoB26Fj4x9LboAFWJra17O"
# Check status for moe
kli status --name moe   --alias threestooges --passcode "DoB26Fj4x9LboAFWJra17O"
# Check status for curly
kli status --name curly --alias threestooges --passcode "DoB26Fj4x9LboAFWJra17O"

echo
print_yellow "Step 6/9 rotate each individual keystore and update keystate - required prior to rotating larry out"
echo

rotate_individual_aids
query_keystate_all_participants


echo
print_yellow "Step 7/9 Rotate larry out of the threestooges AID"
echo

echo
print_yellow "Multisig Rotate - larry out - alias: threestooges"

PID_LIST=""

kli multisig rotate --name larry --alias threestooges \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --smids $LARRY \
  --smids $MOE \
  --smids $CURLY \
  --isith '["1/3", "1/3", "1/3"]' \
  --rmids $MOE \
  --rmids $CURLY \
  --nsith '["1/2", "1/2"]' &
pid=$!
PID_LIST+=" $pid"

kli multisig join --name moe   --passcode "DoB26Fj4x9LboAFWJra17O" --group threestooges --auto &
pid=$!
PID_LIST+=" $pid"
kli multisig join --name curly --passcode "DoB26Fj4x9LboAFWJra17O" --group threestooges --auto &
pid=$!
PID_LIST+=" $pid"

# Uncomment when running by hand (and comment out the above join commands):
#print_lcyan "Run: "
#print_green "  kli multisig join --name moe   --passcode \"DoB26Fj4x9LboAFWJra17O\" --group threestooges"
#print_lcyan "and: "
#print_green "  kli multisig join --name curly --passcode \"DoB26Fj4x9LboAFWJra17O\" --group threestooges"
#print_lcyan "in a terminal from 'keripy/scripts/demo' that has run 'source ./demo-scripts.sh'"
#print_lcyan "and then delete any non-rotation notifications."
#print_lcyan "Then join the multisig rotation proposed by larry"
#read -r -p "Press enter to continue after moe and curly join"

echo
print_yellow "Multisig rotation - larry out - alias: threestooges - wait for signatures"
wait $PID_LIST

# Check status for larry
kli status --name larry --alias threestooges --passcode "DoB26Fj4x9LboAFWJra17O"
# Check status for moe
kli status --name moe   --alias threestooges --passcode "DoB26Fj4x9LboAFWJra17O"
# Check status for curly
kli status --name curly --alias threestooges --passcode "DoB26Fj4x9LboAFWJra17O"


echo
print_yellow "Step 8/9 rotate each individual keystore and update keystate - required prior to rotating alfred in"
echo

rotate_individual_aids
query_keystate_all_participants


echo
print_yellow "Step 9/9 Rotate alfred into the threestooges AID"
echo

# Tell curly about the new multisig AID with OOBI resolve
print_yellow "Resolve threestooges multisig OOBI for curly"
kli oobi resolve --name alfred --oobi-alias threestooges \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$MULTISIG_AID/witness/$WAN_WITNESS_PREFIX
echo

print_yellow "Multisig rotation with alias: threestooges"

PID_LIST=""

print_yellow "moe proposes rotation - bring curly in"
kli multisig rotate --name moe --alias "threestooges" \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --isith '["1/3", "1/3", "1/3"]' \
  --smids $MOE \
  --smids $CURLY \
  --smids $ALFRED \
  --nsith '["1/3", "1/3", "1/3"]' \
  --rmids $MOE \
  --rmids $CURLY \
  --rmids $ALFRED &
pid=$!
PID_LIST+=" $pid"
sleep 1

kli multisig join --name curly --passcode "DoB26Fj4x9LboAFWJra17O" --group threestooges --auto &
pid=$!
PID_LIST+=" $pid"
kli multisig join --name alfred --passcode "DoB26Fj4x9LboAFWJra17O" --group threestooges --auto &
pid=$!
PID_LIST+=" $pid"

# Uncomment when running by hand (and comment out the above join commands):
#print_lcyan "Run: "
#print_green "  kli multisig join --name curly  --passcode \"DoB26Fj4x9LboAFWJra17O\" --group threestooges"
#print_lcyan "and: "
#print_green "  kli multisig join --name alfred --passcode \"DoB26Fj4x9LboAFWJra17O\" --group threestooges"
#print_lcyan "in a terminal from 'keripy/scripts/demo' that has run 'source ./demo-scripts.sh'"
#print_lcyan "and then delete any non-rotation notifications."
#print_lcyan "Then join the multisig rotation proposed by larry"
#read -r -p "Press enter to continue after curly and alfred join"

echo
print_yellow "Multisig rotation threestooges - wait for signatures"
wait $PID_LIST


# Check status of multisig AIDs
# Check status for moe
kli status --name moe    --alias threestooges --passcode "DoB26Fj4x9LboAFWJra17O"
# Check status for curly
kli status --name curly  --alias threestooges --passcode "DoB26Fj4x9LboAFWJra17O"
# Check status for alfred
kli status --name alfred --alias threestooges --passcode "DoB26Fj4x9LboAFWJra17O"

echo
print_green "Multisig rotation - complete"
echo