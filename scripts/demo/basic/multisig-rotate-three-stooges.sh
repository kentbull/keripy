#!/bin/bash
# three stooges

source ${KERI_SCRIPT_DIR}/demo/basic/script-utils.sh

# WITNESSES
# To run the following scripts, open another console window and run:
# $ kli witness demo

print_yellow "Multisig rotation with three AIDs"
echo

kli init --name larry \
  --salt 0ACDEyMzQ1Njc4OWxtbm9aBc \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --config-dir "${KERI_SCRIPT_DIR}" \
  --config-file demo-witness-oobis
# Prefix EA5g3RMwkjcr_M4fI3k2ShCYlQMpgk3HD9mHhx7ZJs4U
kli incept --name larry --alias larry \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-1-sample.json

kli init --name moe \
  --salt 0ACDEyMzQ1Njc4OWdoaWpsaw \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --config-dir "${KERI_SCRIPT_DIR}" \
  --config-file demo-witness-oobis
# Prefix ED7yk9oUIe5qRh8ILfTuT_sNHidrxwJ9Bl-tLPoAXbqW
kli incept --name moe --alias moe \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-2-sample.json

kli init --name curly \
  --salt 0ACDEyMzQ1Njc4OWdoaWpsaw \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --config-dir "${KERI_SCRIPT_DIR}" \
  --config-file demo-witness-oobis
# Prefix EEHyoLseuHa0nuhDj9tBv6N6nU1PILwv4jTt5x8A8uLu
kli incept --name curly --alias curly \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-3-sample.json

# OOBI resolution does the initial discovery of key state
echo
print_yellow "Resolve OOBIs"
kli oobi resolve --name larry --oobi-alias moe \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/ED7yk9oUIe5qRh8ILfTuT_sNHidrxwJ9Bl-tLPoAXbqW/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name larry --oobi-alias curly \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/EEHyoLseuHa0nuhDj9tBv6N6nU1PILwv4jTt5x8A8uLu/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

kli oobi resolve --name moe --oobi-alias larry \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/EA5g3RMwkjcr_M4fI3k2ShCYlQMpgk3HD9mHhx7ZJs4U/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name moe --oobi-alias curly \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/EEHyoLseuHa0nuhDj9tBv6N6nU1PILwv4jTt5x8A8uLu/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

kli oobi resolve --name curly --oobi-alias larry \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/EA5g3RMwkjcr_M4fI3k2ShCYlQMpgk3HD9mHhx7ZJs4U/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name curly --oobi-alias moe \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/ED7yk9oUIe5qRh8ILfTuT_sNHidrxwJ9Bl-tLPoAXbqW/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

# Multisig Inception
echo
print_yellow "Multisig Inception"
# Follow commands run in parallel
kli multisig incept --name larry --alias larry \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --group multisig \
  --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-three-aids.json &
pid=$!
PID_LIST+=" $pid"
kli multisig incept --name moe --alias moe \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --group multisig \
  --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-three-aids.json &
pid=$!
PID_LIST+=" $pid"
kli multisig incept --name curly --alias curly \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --group multisig \
  --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-three-aids.json &
pid=$!
PID_LIST+=" $pid"

echo
print_yellow "Multisig Inception - wait"
wait $PID_LIST

echo
print_green "Multisig Inception - status"
kli status --name larry --alias multisig --passcode "DoB26Fj4x9LboAFWJra17O"

# Rotate keys for each multisig - required before rotating the multisig
echo
print_yellow "Rotate keys for each multisig"
kli rotate --name larry --alias larry --passcode "DoB26Fj4x9LboAFWJra17O"
kli rotate --name moe --alias moe --passcode "DoB26Fj4x9LboAFWJra17O"
kli rotate --name curly --alias curly --passcode "DoB26Fj4x9LboAFWJra17O"

# Pull key state in from other multisig group participant identifiers so they have the next digest
echo
print_yellow "Pull key state in from other multisig group participant identifiers"
# 2 about 1
kli query --name moe --alias moe \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --prefix EA5g3RMwkjcr_M4fI3k2ShCYlQMpgk3HD9mHhx7ZJs4U
# 2 about 3
kli query --name moe --alias moe \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --prefix EEHyoLseuHa0nuhDj9tBv6N6nU1PILwv4jTt5x8A8uLu
# 1 about 2
kli query --name larry --alias larry \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --prefix ED7yk9oUIe5qRh8ILfTuT_sNHidrxwJ9Bl-tLPoAXbqW
# 1 about 3
kli query --name larry --alias larry \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --prefix EEHyoLseuHa0nuhDj9tBv6N6nU1PILwv4jTt5x8A8uLu
# 3 about 1
kli query --name curly --alias curly \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --prefix EA5g3RMwkjcr_M4fI3k2ShCYlQMpgk3HD9mHhx7ZJs4U
# 3 about 2
kli query --name curly --alias curly \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --prefix ED7yk9oUIe5qRh8ILfTuT_sNHidrxwJ9Bl-tLPoAXbqW


echo
print_yellow "Multisig rotation"

PID_LIST=""

kli multisig rotate --name larry --alias multisig \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --isith '["1/3", "1/3", "1/3"]' \
  --smids EA5g3RMwkjcr_M4fI3k2ShCYlQMpgk3HD9mHhx7ZJs4U \
  --smids ED7yk9oUIe5qRh8ILfTuT_sNHidrxwJ9Bl-tLPoAXbqW \
  --smids EEHyoLseuHa0nuhDj9tBv6N6nU1PILwv4jTt5x8A8uLu \
  --nsith '["1/2", "1/2", "1/2"]' \
  --rmids EA5g3RMwkjcr_M4fI3k2ShCYlQMpgk3HD9mHhx7ZJs4U \
  --rmids ED7yk9oUIe5qRh8ILfTuT_sNHidrxwJ9Bl-tLPoAXbqW \
  --rmids EEHyoLseuHa0nuhDj9tBv6N6nU1PILwv4jTt5x8A8uLu &
pid=$!
PID_LIST+=" $pid"
kli multisig rotate --name moe --alias multisig \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --isith '["1/3", "1/3", "1/3"]' \
  --smids EA5g3RMwkjcr_M4fI3k2ShCYlQMpgk3HD9mHhx7ZJs4U \
  --smids ED7yk9oUIe5qRh8ILfTuT_sNHidrxwJ9Bl-tLPoAXbqW \
  --smids EEHyoLseuHa0nuhDj9tBv6N6nU1PILwv4jTt5x8A8uLu \
  --nsith '["1/2", "1/2", "1/2"]' \
  --rmids EA5g3RMwkjcr_M4fI3k2ShCYlQMpgk3HD9mHhx7ZJs4U \
  --rmids ED7yk9oUIe5qRh8ILfTuT_sNHidrxwJ9Bl-tLPoAXbqW \
  --rmids EEHyoLseuHa0nuhDj9tBv6N6nU1PILwv4jTt5x8A8uLu &
pid=$!
PID_LIST+=" $pid"
kli multisig rotate --name curly --alias multisig \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --isith '["1/3", "1/3", "1/3"]' \
  --smids EA5g3RMwkjcr_M4fI3k2ShCYlQMpgk3HD9mHhx7ZJs4U \
  --smids ED7yk9oUIe5qRh8ILfTuT_sNHidrxwJ9Bl-tLPoAXbqW \
  --smids EEHyoLseuHa0nuhDj9tBv6N6nU1PILwv4jTt5x8A8uLu \
  --nsith '["1/2", "1/2", "1/2"]' \
  --rmids EA5g3RMwkjcr_M4fI3k2ShCYlQMpgk3HD9mHhx7ZJs4U \
  --rmids ED7yk9oUIe5qRh8ILfTuT_sNHidrxwJ9Bl-tLPoAXbqW \
  --rmids EEHyoLseuHa0nuhDj9tBv6N6nU1PILwv4jTt5x8A8uLu &
pid=$!
PID_LIST+=" $pid"

echo
print_yellow "Multisig rotation - wait"
wait $PID_LIST

echo
print_green "Multisig rotation - status"
kli status --name larry --alias multisig --passcode "DoB26Fj4x9LboAFWJra17O"

echo
print_yellow "Multisig interact"

PID_LIST=""

kli multisig interact --name larry --alias multisig \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --data "{\"tagline\":\"three lost souls\"}" &
pid=$!
PID_LIST+=" $pid"
kli multisig interact --name moe --alias multisig \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --data "{\"tagline\":\"three lost souls\"}" &
pid=$!
PID_LIST+=" $pid"
kli multisig interact --name curly --alias multisig \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --data "{\"tagline\":\"three lost souls\"}" &
pid=$!
PID_LIST+=" $pid"

echo
print_yellow "Multisig interact - wait"
wait $PID_LIST

echo
print_green "Multisig interact - status"
kli status --name larry --alias multisig --passcode "DoB26Fj4x9LboAFWJra17O"
print_lcyan "Multisig rotate three stooges - done."

