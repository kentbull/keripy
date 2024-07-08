#!/bin/bash
# multisig-rotate-out-and-in.sh
# This file is self contained except for the keystore initialization config file.
# The inception configuration and multisig configuration files are included in the script
# as here docs.
#
# Required services:
# - KERI witness demo nodes running.
#     Use the `kli witness demo` command


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
export WIT_HOST="http://192.168.1.4"

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
  --config-dir "${KERI_SCRIPT_DIR}/../rootgartest" \
  --config-file rootgar-test-oobis
kli incept --name larry --alias larry \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --file "${temp_icp_config}"

rm "$temp_icp_config"

echo
print_yellow "Step 2/9 Add contacts with OOBIs using 'wan' as the witness"
echo
read -r -p "Press [Enter] to resolve OOBIs..."

echo
print_yellow "Resolve OOBIs between all participants (8 total)"
print_yellow "larry -> {moe, curly, alfred}"
kli oobi resolve --name larry --oobi-alias moe \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi "$WIT_HOST:5642/oobi/$MOE/witness/$WAN_WITNESS_PREFIX"
#kli oobi resolve --name larry --oobi-alias curly \
#  --passcode "DoB26Fj4x9LboAFWJra17O" \
#  --oobi "$WIT_HOST:5642/oobi/$CURLY/witness/$WAN_WITNESS_PREFIX"
#kli oobi resolve --name larry --oobi-alias alfred \
#  --passcode "DoB26Fj4x9LboAFWJra17O" \
#  --oobi "$WIT_HOST:5642/oobi/$ALFRED/witness/$WAN_WITNESS_PREFIX"

echo
