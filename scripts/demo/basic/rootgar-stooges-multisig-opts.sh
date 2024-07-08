#!/bin/bash
# multisig-rotate-out-and-in.sh
# This file is self contained except for the keystore initialization config file.
# The inception configuration and multisig configuration files are included in the script
# as here docs.
#
# Required services:
# - KERI witness demo nodes running.
#     Use the `kli witness demo` command


# Next, creates a multisig AID, threestooges, with larry and moe.
# curly is then rotated into the threestooges AID.
# larry is rotated out of the threestooges AID.
# alfred is rotated into the threestooges AID.

trap 'echo "Exiting due to Ctrl+C..."; exit 0;' SIGINT


# Pull in colored text
source "${KERI_SCRIPT_DIR}"/demo/basic/script-utils.sh

# create keystores and AIDs for larry, moe, and curly
export LARRY=EKZYoeLcSpoBn7DdD0Rugk3xGy6in8zJvhJpMhZ23ETe
export MOE=EJ__4LOcMfGRU0V65ywo9GgczMkqTZtgjmCKWU06MDQR
export CURLY=EItXS2M_iaQvYRex9swUaCWLETsxFdQbQD0XZmbukKOV
export ALFRED=ECl8nwhRYub9Se_Caes40ex0vJXi9v84CaydEalEZgH3

# Witness prefix
export WAN_WITNESS_PREFIX=BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

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

function incept() {
  echo
  print_yellow "Step 3/9 Create multisig AID with larry and moe as participants"
  echo

  echo
  print_yellow "Multisig Inception for alias: threestooges with larry and moe"
  # Follow commands run in parallel
  print_yellow "Multisig Inception from larry: ${LARRY}"
  kli multisig incept --name larry --alias larry \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --group "threestooges" \
    --file "${temp_multisig_config}"

#  rm "$temp_multisig_config"

  # Check status for larry
  echo
  print_yellow "Check multisig status for larry"
  kli status --name larry --alias threestooges --passcode "DoB26Fj4x9LboAFWJra17O"
}

function rotate_individual_aids() {
  echo
  print_yellow "Rotate each individual keystore"
  kli rotate --name larry  --alias larry  --passcode "DoB26Fj4x9LboAFWJra17O"
  echo
}

function query_keystate_all_participants() {
  echo
  print_yellow "Pull key state in from other multisig group participant identifiers"
  print_yellow "Key State Query: larry -> {moe, curly, alfred}"
  kli query --name larry --alias larry --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $MOE
#  kli query --name larry --alias larry --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $CURLY
#  kli query --name larry --alias larry --passcode "DoB26Fj4x9LboAFWJra17O" --prefix $ALFRED
  echo
}

function rotate_threestooges() {
  # just rotate
  print_yellow "larry proposes multisig rotation - larry and moe"
  read -r -p "Press enter to continue"
  kli multisig rotate --name larry --alias "threestooges" \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --isith '["1/2", "1/2"]' \
    --smids $LARRY \
    --smids $MOE \
    --nsith '["1/2", "1/2"]' \
    --rmids $LARRY \
    --rmids $MOE
}

function rotate_curly_in() {
  print_yellow "Multisig rotation with alias: threestooges"

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
    --rmids $CURLY

  echo
  # Check status of multisig AIDs
  kli status --name larry --alias threestooges --passcode "DoB26Fj4x9LboAFWJra17O"
}

function rotate_larry_out() {
  echo
  print_yellow "Step 7/9 Rotate larry out of the threestooges AID"
  echo
  read -r -p "Press enter to continue"

  echo
  print_yellow "Multisig Rotate - larry out - alias: threestooges"

  kli multisig rotate --name larry --alias threestooges \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --smids $LARRY \
    --smids $MOE \
    --smids $CURLY \
    --isith '["1/3", "1/3", "1/3"]' \
    --rmids $MOE \
    --rmids $CURLY \
    --nsith '["1/2", "1/2"]'

  echo
  # Check status for larry
  kli status --name larry --alias threestooges --passcode "DoB26Fj4x9LboAFWJra17O"
}

main() {
  read -n 1 -r -p "Press any key to rotate AIDs"
  rotate_individual_aids
  read -n 1 -r -p "Press any key to query key state"
  query_keystate_all_participants

  incept

  rm "$temp_multisig_config"

  echo
  print_yellow "Step 4/9 rotate each individual keystore and update keystate - required prior to performing rotation"
  echo
  read -n 1 -r -p "Press any key to rotate AIDs"
  rotate_individual_aids
  read -n 1 -r -p "Press any key to query key state"
  query_keystate_all_participants

  print_red "early exit"
  exit 0

  echo
  print_yellow "Step 4/9 and 1/2 rotate threestooges - larry and moe"
  rotate_threestooges

  read -n 1 -r -p "Press any key to rotate AIDs"
  rotate_individual_aids
  read -n 1 -r -p "Press any key to query key state"
  query_keystate_all_participants

  echo
  print_yellow "Step 5/9 Rotate curly into the threestooges AID"
  echo
  read -r -p "Press enter to continue"
  rotate_curly_in

  echo
  print_yellow "Step 6/9 rotate each individual keystore and update keystate - required prior to rotating larry out"
  echo

  read -n 1 -r -p "Press any key to rotate AIDs"
  rotate_individual_aids
  read -n 1 -r -p "Press any key to query key state"
  query_keystate_all_participants

  rotate_larry_out

  echo
  print_yellow "Step 8/9 rotate each individual keystore and update keystate - required prior to rotating alfred in"
  echo

  read -n 1 -r -p "Press any key to rotate AIDs"
  rotate_individual_aids
  read -n 1 -r -p "Press any key to query key state"
  query_keystate_all_participants

  echo
  print_green "Multisig rotation - use other computers to rotate alfred in"
  echo
}
main