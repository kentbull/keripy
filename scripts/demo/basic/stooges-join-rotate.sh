#!/bin/bash
# three stooges join a multisig rotate

source "${KERI_SCRIPT_DIR}"/demo/basic/script-utils.sh

# WITNESSES
# To run the following scripts, open another console window and run:
# $ kli witness demo

# create keystores and AIDs for larry, moe, and curly
LARRY=EKZYoeLcSpoBn7DdD0Rugk3xGy6in8zJvhJpMhZ23ETe
MOE=EJ__4LOcMfGRU0V65ywo9GgczMkqTZtgjmCKWU06MDQR
CURLY=EItXS2M_iaQvYRex9swUaCWLETsxFdQbQD0XZmbukKOV

members_incept() {
  INCEPT_CONFIG_FILE=$1
  echo
  print_yellow "Individual AID creation with file: ${INCEPT_CONFIG_FILE}"
  # Larry Prefix EKZYoeLcSpoBn7DdD0Rugk3xGy6in8zJvhJpMhZ23ETe
  kli init --name larry \
    --salt 0ACDEyMzQ1Njc4OWxtbm9aBc \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --config-dir "${KERI_SCRIPT_DIR}" \
    --config-file demo-witness-oobis
  kli incept --name larry --alias larry \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --file "$INCEPT_CONFIG_FILE"

  # Moe Prefix EJ__4LOcMfGRU0V65ywo9GgczMkqTZtgjmCKWU06MDQR
  kli init --name moe \
    --salt 0ACDEyMzQ1Njc4OWdoaWpsaw \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --config-dir "${KERI_SCRIPT_DIR}" \
    --config-file demo-witness-oobis
  kli incept --name moe --alias moe \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --file "$INCEPT_CONFIG_FILE"

  # Curly Prefix EItXS2M_iaQvYRex9swUaCWLETsxFdQbQD0XZmbukKOV
  kli init --name curly \
    --salt 0ACDEyMzQ1Njc4OWdoaWpsaw \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --config-dir "${KERI_SCRIPT_DIR}" \
    --config-file demo-witness-oobis
  kli incept --name curly --alias curly \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --file "$INCEPT_CONFIG_FILE"
  echo
}

# OOBI resolution does the initial discovery of key state
members_oobi_resolve() {
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
}

# Multisig Inception
multisig_incept() {
  MULTISIG_ALIAS=${1:-"default alias"}
  MULTISIG_ICP_CONFIG_FILE=$2
  echo
  print_yellow "Multisig Inception for alias: ${MULTISIG_ALIAS}"
  print_yellow "Multisig Inception with file: ${MULTISIG_ICP_CONFIG_FILE}"
  # Follow commands run in parallel
  kli multisig incept --name larry --alias larry \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --group "${MULTISIG_ALIAS}" \
    --file "${MULTISIG_ICP_CONFIG_FILE}" &
  pid=$!
  PID_LIST+=" $pid"
  kli multisig incept --name moe --alias moe \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --group "${MULTISIG_ALIAS}" \
    --file "${MULTISIG_ICP_CONFIG_FILE}" &
  pid=$!
  PID_LIST+=" $pid"
  kli multisig incept --name curly --alias curly \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --group "${MULTISIG_ALIAS}" \
    --file "${MULTISIG_ICP_CONFIG_FILE}" &
  pid=$!
  PID_LIST+=" $pid"

  echo
  print_yellow "Multisig Inception - wait"
  echo
  wait $PID_LIST
}

multisig_incept_join() {
  MULTISIG_ALIAS=${1:-"default alias"}
  MULTISIG_ICP_CONFIG_FILE=$2
  echo
  print_yellow "Multisig Inception with join for alias: ${MULTISIG_ALIAS}"
  print_yellow "Multisig Inception with file: ${MULTISIG_ICP_CONFIG_FILE}"
  kli multisig incept --name larry --alias larry --group "$MULTISIG_ALIAS" \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --file "${MULTISIG_ICP_CONFIG_FILE}" &
    
  pid=$!
  PID_LIST+=" $pid"
  
  kli multisig join --name moe --passcode "DoB26Fj4x9LboAFWJra17O" --auto &
  pid=$!
  PID_LIST+=" $pid"
  kli multisig join --name curly --passcode "DoB26Fj4x9LboAFWJra17O" --auto &
  pid=$!
  PID_LIST+=" $pid"
  
  echo
  print_yellow "Multisig Inception with join - wait"
  wait $PID_LIST
  echo
}

multisig_incept_join_two() {
  MULTISIG_ALIAS=${1:-"default alias"}
  MULTISIG_ICP_CONFIG_FILE=$2
  echo
  print_yellow "Multisig Inception with join for alias: ${MULTISIG_ALIAS}"
  print_yellow "Multisig Inception with file: ${MULTISIG_ICP_CONFIG_FILE}"
  kli multisig incept --name larry --alias larry --group "$MULTISIG_ALIAS" \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --file "${MULTISIG_ICP_CONFIG_FILE}" &

  pid=$!
  PID_LIST+=" $pid"

  kli multisig join --name moe --passcode "DoB26Fj4x9LboAFWJra17O" --auto &
  pid=$!
  PID_LIST+=" $pid"

  echo
  print_yellow "Multisig Inception with join - wait"
  wait $PID_LIST
  echo
}

# Multisig Inception - status
multisig_status() {
  KEYSTORE=$1
  MULTISIG_ALIAS=$2
  echo
  print_green "Multisig status for ${KEYSTORE} on alias: ${MULTISIG_ALIAS}"
  kli status --name "${KEYSTORE}" --alias "${MULTISIG_ALIAS}" --passcode "DoB26Fj4x9LboAFWJra17O"
  echo
}

# Rotate keys for each multisig - required before rotating the multisig
rotate_individual_keys() {
  echo
  print_yellow "Rotate keys for each multisig"
  kli rotate --name larry --alias larry --passcode "DoB26Fj4x9LboAFWJra17O"
  kli rotate --name moe   --alias moe   --passcode "DoB26Fj4x9LboAFWJra17O"
  kli rotate --name curly --alias curly --passcode "DoB26Fj4x9LboAFWJra17O"
  echo
}

# Pull key state in from other multisig group participant identifiers so they have the next digest
query_individual_keystate() {
  echo
  print_yellow "Pull key state in from other multisig group participant identifiers"
  # 1 about 2
  print_yellow "Larry queries Moe"
  kli query --name larry --alias larry \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --prefix $MOE
  # 1 about 3
  print_yellow "Larry queries Curly"
  kli query --name larry --alias larry \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --prefix $CURLY
  # 2 about 1
  print_yellow "Moe queries Larry"
  kli query --name moe --alias moe \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --prefix $LARRY
  # 2 about 3
  print_yellow "Moe queries Curly"
  kli query --name moe --alias moe \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --prefix $CURLY
  # 3 about 1
  print_yellow "Curly queries Larry"
  kli query --name curly --alias curly \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --prefix $LARRY
  # 3 about 2
  print_yellow "Curly queries Moe"
  kli query --name curly --alias curly \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --prefix $MOE
  echo
}

# Does a multisig rotate where all members prepare the same rotation event
multisig_rotate_three() {
  MULTISIG_ALIAS=${1:-"default alias"}
  echo
  print_yellow "Multisig rotation with alias: ${MULTISIG_ALIAS}"

  PID_LIST=""

  kli multisig rotate --name larry --alias "${MULTISIG_ALIAS}" \
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
  kli multisig rotate --name moe --alias "${MULTISIG_ALIAS}" \
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
  kli multisig rotate --name curly --alias "${MULTISIG_ALIAS}" \
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

  echo
  print_yellow "Multisig rotation ${ALIAS} - wait"
  wait $PID_LIST
}

# Does a multisig rotate where one member prepares the rotation event and sends it to the others
# to which they respond through multisig join
multisig_rotate_join_three() {
  MULTISIG_ALIAS=${1:-"default alias"}
  echo
  print_yellow "Multisig rotation"

  PID_LIST=""

  kli multisig rotate --name larry --alias "${MULTISIG_ALIAS}" \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --smids $LARRY \
    --smids $MOE \
    --smids $CURLY \
    --isith '["1/3", "1/3", "1/3"]' \
    --rmids $LARRY \
    --rmids $MOE \
    --rmids $CURLY \
    --nsith '["1/3", "1/3", "1/3"]' &
  pid=$!
  PID_LIST+=" $pid"

  kli multisig join --name moe --passcode "DoB26Fj4x9LboAFWJra17O" --auto &
  pid=$!
  PID_LIST+=" $pid"

  kli multisig join --name curly --passcode "DoB26Fj4x9LboAFWJra17O" --auto &
  pid=$!
  PID_LIST+=" $pid"

  echo
  print_yellow "Multisig rotation - wait"
  wait $PID_LIST
}

multisig_rotate_join_two() {
  MULTISIG_ALIAS=${1:-"default alias"}
  echo
  print_yellow "Multisig rotation"

  PID_LIST=""

  kli multisig rotate --name larry --alias "${MULTISIG_ALIAS}" \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --smids $LARRY \
    --smids $MOE \
    --isith '["1/2", "1/2"]' \
    --rmids $LARRY \
    --rmids $MOE \
    --rmids $CURLY \
    --nsith '["1/3", "1/3", "1/3"]' &
#    --nsith '["1/2", "1/2"]' &
  pid=$!
  PID_LIST+=" $pid"

  kli multisig join --name moe --passcode "DoB26Fj4x9LboAFWJra17O" --auto &
  pid=$!
  PID_LIST+=" $pid"

  kli multisig join --name curly --passcode "DoB26Fj4x9LboAFWJra17O" --auto &
  pid=$!
  PID_LIST+=" $pid"

  echo
  print_yellow "Multisig rotation - wait"
  wait $PID_LIST
}

multisig_interact() {
  MULTISIG_ALIAS=${1:-"default alias"}
  data=$2
  echo
  print_yellow "Multisig interact"

  PID_LIST=""

  kli multisig interact --name larry --alias "${MULTISIG_ALIAS}" \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --data "$data" &
  pid=$!
  PID_LIST+=" $pid"
  kli multisig interact --name moe --alias "${MULTISIG_ALIAS}" \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --data "$data" &
  pid=$!
  PID_LIST+=" $pid"
  kli multisig interact --name curly --alias "${MULTISIG_ALIAS}" \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --data "$data" &
  pid=$!
  PID_LIST+=" $pid"

  echo
  print_yellow "Multisig interact - wait"
  wait $PID_LIST

}

multisig_interact_join() {
  MULTISIG_ALIAS=${1:-"default alias"}
  DATA=$2
  echo
  print_yellow "Multisig interact with join"

  PID_LIST=""

  kli multisig interact --name larry --alias "${MULTISIG_ALIAS}" \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --data "${DATA}" &
  pid=$!
  PID_LIST+=" $pid"

  kli multisig join --name moe   --passcode "DoB26Fj4x9LboAFWJra17O" --auto &
  pid=$!
  PID_LIST+=" $pid"

  kli multisig join --name curly --passcode "DoB26Fj4x9LboAFWJra17O" --auto &
  pid=$!
  PID_LIST+=" $pid"

  echo
  print_yellow "Multisig interact with join - waiting on group"
  wait $PID_LIST
}

rotate_larry_out() {
  MULTISIG_ALIAS=${1:-"default alias"}
  echo
  print_yellow "Multisig Rotate - Larry out - alias: ${MULTISIG_ALIAS}"

  PID_LIST=""

  kli multisig rotate --name larry --alias "${MULTISIG_ALIAS}" \
    --passcode "DoB26Fj4x9LboAFWJra17O" \
    --smids $LARRY \
    --smids $MOE \
    --smids $CURLY \
    --isith '["1/3", "1/3", "1/3"]' \
    --rmids $MOE \
    --rmids $CURLY \
    --nsith '["1/2", "1/2"]' &
#  kli multisig rotate --name moe --alias "${MULTISIG_ALIAS}" \
#    --passcode "DoB26Fj4x9LboAFWJra17O" \
#    --smids $MOE \
#    --smids $CURLY \
#    --isith '["1/2", "1/2"]' \
#    --rmids $MOE \
#    --rmids $CURLY \
#    --rmids $LARRY \
#    --nsith '["1/3", "1/3", "1/3"]' &
  pid=$!
  PID_LIST+=" $pid"

  kli multisig join --name moe --passcode "DoB26Fj4x9LboAFWJra17O" --auto &
  pid=$!
  PID_LIST+=" $pid"

  kli multisig join --name curly --passcode "DoB26Fj4x9LboAFWJra17O" --auto &
  pid=$!
  PID_LIST+=" $pid"

  echo
  print_yellow "Multisig rotation - Larry out - alias: ${MULTISIG_ALIAS} - wait"
  wait $PID_LIST
}

main_three_stooges() {
  print_yellow "Multisig rotation via join with three AIDs, one to start, two join later"
  MULTISIG_ALIAS="multisig"
  # Setup members
  members_incept "${KERI_DEMO_SCRIPT_DIR}/data/multisig-stooge.json"
  members_oobi_resolve

  # Setup multisig
  # multisig_incept "${MULTISIG_ALIAS}" "${KERI_DEMO_SCRIPT_DIR}/data/multisig-three-stooges.json"
  multisig_incept_join "${MULTISIG_ALIAS}" "${KERI_DEMO_SCRIPT_DIR}/data/multisig-three-stooges.json"
  multisig_status larry "${MULTISIG_ALIAS}"

  # Prepare individual AIDs for multisig rotation
  rotate_individual_keys
  query_individual_keystate

  # Rotate Multisig with join
  # multisig_rotate "${MULTISIG_ALIAS}"
  multisig_rotate_join_three "${MULTISIG_ALIAS}"
  multisig_status larry "${MULTISIG_ALIAS}"

  # Interact with multisig
  # multisig_interact "${MULTISIG_ALIAS}" "{\"tagline\":\"three lost souls\"}"
  multisig_interact_join "${MULTISIG_ALIAS}" "{\"tagline\":\"three lost souls\"}"
  multisig_status larry "${MULTISIG_ALIAS}"

  # rotate individual keys again, query key state, prep for rotation
  rotate_individual_keys
  query_individual_keystate

  multisig_status larry "${MULTISIG_ALIAS}"

  print_green "Ready for citadel rotation"
  print_lcyan "Multisig rotate three stooges - done."
}

main_two_stooges_rotate_in_and_out() {
  print_yellow "Multisig rotation via join with three AIDs, two to start, one joins later"
  MULTISIG_ALIAS="multisig"
  # Setup members
  members_incept "${KERI_DEMO_SCRIPT_DIR}/data/multisig-stooge.json"
  members_oobi_resolve

  # Setup multisig
  multisig_incept_join_two \
    "${MULTISIG_ALIAS}" \
    "${KERI_DEMO_SCRIPT_DIR}/data/multisig-two-stooges.json"
  multisig_status larry "${MULTISIG_ALIAS}"

  # Prepare individual AIDs for multisig rotation
  rotate_individual_keys
  query_individual_keystate

  print_green "Exiting early"
  exit 0

  # Rotate Multisig with join
  multisig_rotate_join_two "${MULTISIG_ALIAS}"
  multisig_status larry "${MULTISIG_ALIAS}"

  # Interact with multisig
#  multisig_interact_join "${MULTISIG_ALIAS}" "{\"tagline\":\"three lost souls\"}"
#  multisig_status larry "${MULTISIG_ALIAS}"

#  rotate individual keys again, query keystate, prep for rotation
  rotate_individual_keys
  query_individual_keystate

  rotate_larry_out ${MULTISIG_ALIAS}
  multisig_status larry "${MULTISIG_ALIAS}"
  multisig_status moe "test alias"

  print_green "Ready for citadel rotation"
  print_lcyan "Multisig rotate three stooges - done."
}
#main_three_stooges
main_two_stooges_rotate_in_and_out