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


# This script creates four AIDs, rootgar1, rootgar2, rootgar3, and rootgar4.
# Next, creates a multisig AID, rootgarmulti, with rootgar1 and rootgar2.
# rootgar3 is then rotated into the rootgarmulti AID.
# rootgar1 is rotated out of the rootgarmulti AID.
# rootgar4 is rotated into the rootgarmulti AID.


# Pull in colored text
source "${KERI_SCRIPT_DIR}"/demo/basic/script-utils.sh

# create keystores and AIDs for rootgar1, rootgar2, and rootgar3
export rootgar1=EBiezHEM0j2kfb58M4kbd3fG1lTg0crLmmfis_UXdn41
export rootgar2=EAn0ufTdhwHvQNWw-PBdz-jHAYC5_Ic3ndHGqRfodG0m
export rootgar3=EMTLiOHsiz8JfTW7g0FSFoqGcHFSaVTFGCsoJaI0OBeC
export rootgar4=EL-S2jdZag7vG6aqnVXJr_Krzd00g0aN2WOJ2ALy46XF

# Witness prefix
export WAN_WITNESS_PREFIX=BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

echo
print_yellow "Step 1/9 Create AIDs rootgar1, rootgar2, rootgar3, and rootgar4"
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
print_green "rootgar1: ${rootgar1}"
# rootgar1 Prefix EKZYoeLcSpoBn7DdD0Rugk3xGy6in8zJvhJpMhZ23ETe
kli init --name rootgar1 \
  --salt 0ACDEyMzQ1Njc4OWxtbm9aBc \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --config-dir "${KERI_SCRIPT_DIR}" \
  --config-file demo-witness-oobis
kli incept --name rootgar1 --alias rootgar1 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --file "${temp_icp_config}"

# rootgar2 Prefix EJ__4LOcMfGRU0V65ywo9GgczMkqTZtgjmCKWU06MDQR
print_green "rootgar2: ${rootgar2}"
kli init --name rootgar2 \
  --salt 0ACDEyMzQ1Njc4OWdoaWpsaw \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --config-dir "${KERI_SCRIPT_DIR}" \
  --config-file demo-witness-oobis
kli incept --name rootgar2 --alias rootgar2 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --file "${temp_icp_config}"

# rootgar3 Prefix EItXS2M_iaQvYRex9swUaCWLETsxFdQbQD0XZmbukKOV
print_green "rootgar3: ${rootgar3}"
kli init --name rootgar3 \
  --salt 0ACDEyMzQ1Njc4OWdoaWpsaw \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --config-dir "${KERI_SCRIPT_DIR}" \
  --config-file demo-witness-oobis
kli incept --name rootgar3 --alias rootgar3 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --file "${temp_icp_config}"
echo

# rootgar4 Prefix EItXS2M_iaQvYRex9swUaCWLETsxFdQbQD0XZmbukKOV
print_green "rootgar4: ${rootgar4}"
kli init --name rootgar4 \
  --salt 0ACDEyMzQ1Njc4OWdoaWpsaw \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --config-dir "${KERI_SCRIPT_DIR}" \
  --config-file demo-witness-oobis
kli incept --name rootgar4 --alias rootgar4 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --file "${temp_icp_config}"
echo

rm "$temp_icp_config"

echo
print_yellow "Step 2/9 Add contacts with OOBIs using 'wan' as the witness"
echo

echo
print_yellow "Resolve OOBIs between all participants (8 total)"
print_yellow "rootgar1 -> {rootgar2, rootgar3, rootgar4}"
kli oobi resolve --name rootgar1 --oobi-alias rootgar2 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$rootgar2/witness/$WAN_WITNESS_PREFIX
kli oobi resolve --name rootgar1 --oobi-alias rootgar3 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$rootgar3/witness/$WAN_WITNESS_PREFIX
kli oobi resolve --name rootgar1 --oobi-alias rootgar4 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$rootgar4/witness/$WAN_WITNESS_PREFIX

print_yellow "rootgar2 -> {rootgar1, rootgar3, rootgar4}"
kli oobi resolve --name rootgar2 --oobi-alias rootgar1 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$rootgar1/witness/$WAN_WITNESS_PREFIX
kli oobi resolve --name rootgar2 --oobi-alias rootgar3 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$rootgar3/witness/$WAN_WITNESS_PREFIX
kli oobi resolve --name rootgar2 --oobi-alias rootgar4 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$rootgar4/witness/$WAN_WITNESS_PREFIX

print_yellow "rootgar3 -> {rootgar1, rootgar2, rootgar4}"
kli oobi resolve --name rootgar3 --oobi-alias rootgar1 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$rootgar1/witness/$WAN_WITNESS_PREFIX
kli oobi resolve --name rootgar3 --oobi-alias rootgar2 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$rootgar2/witness/$WAN_WITNESS_PREFIX
kli oobi resolve --name rootgar3 --oobi-alias rootgar4 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$rootgar4/witness/$WAN_WITNESS_PREFIX

print_yellow "rootgar4 -> {rootgar1, rootgar2, rootgar3}"
kli oobi resolve --name rootgar4 --oobi-alias rootgar1 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$rootgar1/witness/$WAN_WITNESS_PREFIX
kli oobi resolve --name rootgar4 --oobi-alias rootgar2 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$rootgar2/witness/$WAN_WITNESS_PREFIX
kli oobi resolve --name rootgar4 --oobi-alias rootgar3 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$rootgar3/witness/$WAN_WITNESS_PREFIX

echo


echo
print_yellow "Step 3/9 Create multisig AID with rootgar1 and rootgar2 as participants"
echo

echo
print_yellow "Multisig Inception for alias: rootgarmulti with rootgar1 and rootgar2"

# store multisig-two-stooges.json as a variable
print_yellow "Multisig Inception temp config file."
read -r -d '' MULTISIG_ICP_CONFIG_JSON << EOM
{
  "aids": [
    "$rootgar1",
    "$rootgar2"
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
print_yellow "Multisig Inception from rootgar1: ${rootgar1}"
kli multisig incept --name rootgar1 --alias rootgar1 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --group "rootgarmulti" \
  --file "${temp_multisig_config}" &
pid=$!
PID_LIST+=" $pid"

echo


kli multisig join --name rootgar2  --passcode "DoB26Fj4x9LboAFWJra17O" --group rootgarmulti --auto &
pid=$!
PID_LIST+=" $pid"

# Uncomment when running by hand (and comment out the above join command):
#print_lcyan "Run: "
#print_green "  kli multisig join --name rootgar2   --passcode \"DoB26Fj4x9LboAFWJra17O\" --group rootgarmulti"
#print_lcyan "in a terminal from 'keripy/scripts/demo' that has run 'source ./demo-scripts.sh'"
#read -r -p "Press enter to continue after rootgar2 joins the inception"

echo
print_yellow "Multisig Inception {rootgar1, rootgar2} - wait for signatures"
echo
wait $PID_LIST

rm "$temp_multisig_config"

# Check status for rootgar1
echo
print_yellow "Check multisig status for rootgar1"
kli status --name rootgar1 --alias rootgarmulti --passcode "DoB26Fj4x9LboAFWJra17O"
print_yellow "Check multisig status for rootgar2"
kli status --name rootgar2   --alias rootgarmulti --passcode "DoB26Fj4x9LboAFWJra17O"
echo


echo
print_yellow "Step 4/9 rotate each individual keystore and update keystate - required prior to performing rotation"
echo

function rotate_individual_aids() {
  echo
  print_yellow "Rotate each individual keystore"
  kli rotate --name rootgar1  --alias rootgar1  --passcode "DoB26Fj4x9LboAFWJra17O"
  kli rotate --name rootgar2    --alias rootgar2    --passcode "DoB26Fj4x9LboAFWJra17O"
  kli rotate --name rootgar3  --alias rootgar3  --passcode "DoB26Fj4x9LboAFWJra17O"
  kli rotate --name rootgar4 --alias rootgar4 --passcode "DoB26Fj4x9LboAFWJra17O"
  echo
}

function query_keystate_all_participants() {
  echo
  print_yellow "Pull key state in from other multisig group participant identifiers"
  print_yellow "Key State Query: rootgar1 -> {rootgar2, rootgar3, rootgar4}"
  kli query --name rootgar1 --alias rootgar1 --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $rootgar2
  kli query --name rootgar1 --alias rootgar1 --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $rootgar3
  kli query --name rootgar1 --alias rootgar1 --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $rootgar4

  print_yellow "Key State Query: rootgar2 -> {rootgar1, rootgar3, rootgar4}"
  kli query --name rootgar2   --alias rootgar2   --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $rootgar1
  kli query --name rootgar2   --alias rootgar2   --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $rootgar3
  kli query --name rootgar2   --alias rootgar2   --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $rootgar4

  print_yellow "Key State Query: rootgar3 -> {rootgar1, rootgar2, rootgar4}"
  kli query --name rootgar3 --alias rootgar3 --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $rootgar1
  kli query --name rootgar3 --alias rootgar3 --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $rootgar2
  kli query --name rootgar3 --alias rootgar3 --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $rootgar4

  print_yellow "Key State Query: rootgar4 -> {rootgar1, rootgar2, rootgar3}"
  kli query --name rootgar4 --alias rootgar4 --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $rootgar1
  kli query --name rootgar4 --alias rootgar4 --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $rootgar2
  kli query --name rootgar4 --alias rootgar4 --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $rootgar3
  echo
}

rotate_individual_aids
query_keystate_all_participants

echo
print_yellow "Step 5/9 Rotate rootgar3 into the rootgarmulti AID"
echo

#MULTISIG_AID=EGRRbB0Heh3rbyfCnf7vdbYWbKwWASZboMrMtAnGkDDA
MULTISIG_AID=EAvWXlkDgUMdyqceYKfIbhMBVicc741ORI00itkrRtx6

print_yellow "Multisig rotation with alias: rootgarmulti"

PID_LIST=""

print_yellow "rootgar1 proposes rotation - bring rootgar3 in"
kli multisig rotate --name rootgar1 --alias "rootgarmulti" \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --isith '["1/3", "1/3", "1/3"]' \
  --smids $rootgar1 \
  --smids $rootgar2 \
  --smids $rootgar3 \
  --nsith '["1/3", "1/3", "1/3"]' \
  --rmids $rootgar1 \
  --rmids $rootgar2 \
  --rmids $rootgar3 &
pid=$!
PID_LIST+=" $pid"
sleep 1

kli multisig join --name rootgar2  --passcode "DoB26Fj4x9LboAFWJra17O" --group rootgarmulti --auto &
pid=$!
PID_LIST+=" $pid"

# Tell rootgar3 about the new multisig AID with OOBI resolve
print_yellow "Resolve rootgarmulti multisig OOBI for rootgar3"
kli oobi resolve --name rootgar3 --oobi-alias rootgarmulti \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$MULTISIG_AID/witness/$WAN_WITNESS_PREFIX
echo

kli multisig join --name rootgar3 --passcode "DoB26Fj4x9LboAFWJra17O" --group rootgarmulti --auto &
pid=$!
PID_LIST+=" $pid"

# Uncomment when running by hand (and comment out the above join commands):
#print_lcyan "Run: "
#print_green "  kli multisig join --name rootgar2   --passcode \"DoB26Fj4x9LboAFWJra17O\" --group rootgarmulti"
#print_lcyan "and: "
#print_green "  kli multisig join --name rootgar3 --passcode \"DoB26Fj4x9LboAFWJra17O\" --group rootgarmulti"
#print_lcyan "in a terminal from 'keripy/scripts/demo' that has run 'source ./demo-scripts.sh'"
#print_lcyan "and then delete any non-rotation notifications."
#print_lcyan "Then join the multisig rotation proposed by rootgar1"
#read -r -p "Press enter to continue after rootgar2 and rootgar3 join"

echo
print_yellow "Multisig rotation rootgarmulti - wait for signatures"
wait $PID_LIST


# Check status of multisig AIDs
# Check status for rootgar1
kli status --name rootgar1 --alias rootgarmulti --passcode "DoB26Fj4x9LboAFWJra17O"
# Check status for rootgar2
kli status --name rootgar2   --alias rootgarmulti --passcode "DoB26Fj4x9LboAFWJra17O"
# Check status for rootgar3
kli status --name rootgar3 --alias rootgarmulti --passcode "DoB26Fj4x9LboAFWJra17O"

echo
print_yellow "Step 6/9 rotate each individual keystore and update keystate - required prior to rotating rootgar1 out"
echo

rotate_individual_aids
query_keystate_all_participants


echo
print_yellow "Step 7/9 Rotate rootgar1 out of the rootgarmulti AID"
echo


print_red "early exit"
exit 0

echo
print_yellow "Multisig Rotate - rootgar1 out - alias: rootgarmulti"

PID_LIST=""

kli multisig rotate --name rootgar1 --alias rootgarmulti \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --smids $rootgar1 \
  --smids $rootgar2 \
  --smids $rootgar3 \
  --isith '["1/3", "1/3", "1/3"]' \
  --rmids $rootgar2 \
  --rmids $rootgar3 \
  --nsith '["1/2", "1/2"]' &
pid=$!
PID_LIST+=" $pid"

kli multisig join --name rootgar2   --passcode "DoB26Fj4x9LboAFWJra17O" --group rootgarmulti --auto &
pid=$!
PID_LIST+=" $pid"
kli multisig join --name rootgar3 --passcode "DoB26Fj4x9LboAFWJra17O" --group rootgarmulti --auto &
pid=$!
PID_LIST+=" $pid"

# Uncomment when running by hand (and comment out the above join commands):
#print_lcyan "Run: "
#print_green "  kli multisig join --name rootgar2   --passcode \"DoB26Fj4x9LboAFWJra17O\" --group rootgarmulti"
#print_lcyan "and: "
#print_green "  kli multisig join --name rootgar3 --passcode \"DoB26Fj4x9LboAFWJra17O\" --group rootgarmulti"
#print_lcyan "in a terminal from 'keripy/scripts/demo' that has run 'source ./demo-scripts.sh'"
#print_lcyan "and then delete any non-rotation notifications."
#print_lcyan "Then join the multisig rotation proposed by rootgar1"
#read -r -p "Press enter to continue after rootgar2 and rootgar3 join"

echo
print_yellow "Multisig rotation - rootgar1 out - alias: rootgarmulti - wait for signatures"
wait $PID_LIST

# Check status for rootgar1
kli status --name rootgar1 --alias rootgarmulti --passcode "DoB26Fj4x9LboAFWJra17O"
# Check status for rootgar2
kli status --name rootgar2   --alias rootgarmulti --passcode "DoB26Fj4x9LboAFWJra17O"
# Check status for rootgar3
kli status --name rootgar3 --alias rootgarmulti --passcode "DoB26Fj4x9LboAFWJra17O"


echo
print_yellow "Step 8/9 rotate each individual keystore and update keystate - required prior to rotating rootgar4 in"
echo

rotate_individual_aids
query_keystate_all_participants


echo
print_yellow "Step 9/9 Rotate rootgar4 into the rootgarmulti AID"
echo

# Tell rootgar3 about the new multisig AID with OOBI resolve
print_yellow "Resolve rootgarmulti multisig OOBI for rootgar3"
kli oobi resolve --name rootgar4 --oobi-alias rootgarmulti \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$MULTISIG_AID/witness/$WAN_WITNESS_PREFIX
echo

print_yellow "Multisig rotation with alias: rootgarmulti"

PID_LIST=""

kli multisig rotate --name rootgar2 --alias "rootgarmulti" \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --isith '["1/2", "1/2"]' \
  --smids $rootgar2 \
  --smids $rootgar3 \
  --nsith '["1/2", "1/2"]' \
  --rmids $rootgar2 \
  --rmids $rootgar3

print_yellow "rootgar2 proposes rotation - bring rootgar4 in"
kli multisig rotate --name rootgar2 --alias "rootgarmulti" \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --isith '["1/3", "1/3", "1/3"]' \
  --smids $rootgar2 \
  --smids $rootgar3 \
  --smids $rootgar4 \
  --nsith '["1/3", "1/3", "1/3"]' \
  --rmids $rootgar2 \
  --rmids $rootgar3 \
  --rmids $rootgar4 &
pid=$!
PID_LIST+=" $pid"
sleep 1

kli multisig join --name rootgar3 --passcode "DoB26Fj4x9LboAFWJra17O" --group rootgarmulti --auto &
pid=$!
PID_LIST+=" $pid"
kli multisig join --name rootgar4 --passcode "DoB26Fj4x9LboAFWJra17O" --group rootgarmulti --auto &
pid=$!
PID_LIST+=" $pid"

# Uncomment when running by hand (and comment out the above join commands):
#print_lcyan "Run: "
#print_green "  kli multisig join --name rootgar3  --passcode \"DoB26Fj4x9LboAFWJra17O\" --group rootgarmulti"
#print_lcyan "and: "
#print_green "  kli multisig join --name rootgar4 --passcode \"DoB26Fj4x9LboAFWJra17O\" --group rootgarmulti"
#print_lcyan "in a terminal from 'keripy/scripts/demo' that has run 'source ./demo-scripts.sh'"
#print_lcyan "and then delete any non-rotation notifications."
#print_lcyan "Then join the multisig rotation proposed by rootgar1"
#read -r -p "Press enter to continue after rootgar3 and rootgar4 join"

echo
print_yellow "Multisig rotation rootgarmulti - wait for signatures"
wait $PID_LIST


# Check status of multisig AIDs
# Check status for rootgar2
kli status --name rootgar2    --alias rootgarmulti --passcode "DoB26Fj4x9LboAFWJra17O"
# Check status for rootgar3
kli status --name rootgar3  --alias rootgarmulti --passcode "DoB26Fj4x9LboAFWJra17O"
# Check status for rootgar4
kli status --name rootgar4 --alias rootgarmulti --passcode "DoB26Fj4x9LboAFWJra17O"

echo
print_green "Multisig rotation - complete"
echo