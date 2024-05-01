#!/usr/bin/env bash
# multisig-rotation-with-join.sh

KERI_HOME="$HOME/.keri"

cleanup() {
  rm -fv $KERI_HOME/cf/multisig1.json
  rm -fv $KERI_HOME/cf/multisig2.json
  rm -fv $KERI_HOME/cf/multisig3.json
  rm -rfv $KERI_HOME/db/{multisig1,multisig2,multisig3}
  rm -rfv $KERI_HOME/ks/{multisig1,multisig2,multisig3}
  rm -rfv $KERI_HOME/reg/{multisig1,multisig2,multisig3}
  rm -rfv $KERI_HOME/mbx/{multisig1,multisig2,multisig3}
  rm -rfv $KERI_HOME/not/{multisig1,multisig2,multisig3}
}

print_green() {
  text=$1
  printf "\e[32m${text}\e[0m\n"
}

print_yellow(){
  text=$1
  printf "\e[33m${text}\e[0m\n"
}

print_red() {
  text=$1
  printf "\e[31m${text}\e[0m\n"
}

print_lcyan() {
  text=$1
  printf "\e[96m${text}\e[0m\n"
}

echo
export WAN_WIT_PREFIX=BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
export WIT_HOST=http://127.0.0.1:5642

echo
print_yellow "Using WAN witness prefix: ${WAN_WIT_PREFIX}"
print_yellow "Using Witness Host: ${WIT_HOST}"
# This requires the demo Witnesses to be running
# To run the following scripts, open another console window and run:
# $ kli witness demo


create_identifiers() {
  echo
  print_yellow "Creating Identifiers"
  echo

  # Prefix EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4
  kli init --name multisig1 \
    --salt 0ACDEyMzQ1Njc4OWxtbm9aBc \
    --nopasscode \
    --config-dir "${KERI_SCRIPT_DIR}" \
    --config-file demo-witness-oobis
  kli incept --name multisig1 \
    --alias multisig1 \
    --file "${KERI_DEMO_SCRIPT_DIR}"/data/multisig-1-sample.json
  export MS1_PRE=EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4

  # Prefix EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1
  kli init --name multisig2 \
    --salt 0ACDEyMzQ1Njc4OWdoaWpsaw \
    --nopasscode \
    --config-dir "${KERI_SCRIPT_DIR}" \
    --config-file demo-witness-oobis
  kli incept --name multisig2 \
    --alias multisig2 \
    --file "${KERI_DEMO_SCRIPT_DIR}"/data/multisig-2-sample.json
  export MS2_PRE=EJccSRTfXYF6wrUVuenAIHzwcx3hJugeiJsEKmndi5q1

  # Prefix ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U
  kli init --name multisig3 \
    --salt 0ACDEyMzQ1Njc4OWdoaWpsaw \
    --nopasscode \
    --config-dir "${KERI_SCRIPT_DIR}" \
    --config-file demo-witness-oobis
  kli incept --name multisig3 \
    --alias multisig3 \
    --file "${KERI_DEMO_SCRIPT_DIR}"/data/multisig-3-sample.json
  export MS3_PRE=ENkjt7khEI5edCMw5qugagbJw1QvGnQEtcewxb0FnU9U

  echo
  print_green "Multisig 1 Prefix: ${MS1_PRE}"
  print_green "Multisig 2 Prefix: ${MS2_PRE}"
  print_green "Multisig 3 Prefix: ${MS3_PRE}"
  echo
}

resolve_oobis() {
  print_yellow "Resolving OOBIs"
  echo

  print_yellow "multisig 1 -> 2 and 3"
  kli oobi resolve --name multisig1 \
    --oobi-alias multisig2 \
    --oobi "${WIT_HOST}/oobi/${MS2_PRE}/witness/${WAN_WIT_PREFIX}"
  kli oobi resolve --name multisig1 \
    --oobi-alias multisig3 \
    --oobi "${WIT_HOST}/oobi/${MS3_PRE}/witness/${WAN_WIT_PREFIX}"

  print_yellow "multisig 2 -> 1 and 3"
  kli oobi resolve --name multisig2 \
    --oobi-alias multisig1 \
    --oobi "${WIT_HOST}/oobi/${MS1_PRE}/witness/${WAN_WIT_PREFIX}"
  kli oobi resolve --name multisig2 \
    --oobi-alias multisig3 \
    --oobi "${WIT_HOST}/oobi/${MS3_PRE}/witness/${WAN_WIT_PREFIX}"

  print_yellow "multisig 3 -> 1 and 2"
  kli oobi resolve --name multisig3 \
    --oobi-alias multisig1 \
    --oobi "${WIT_HOST}/oobi/${MS1_PRE}/witness/${WAN_WIT_PREFIX}"
  kli oobi resolve --name multisig3 \
    --oobi-alias multisig2 \
    --oobi "${WIT_HOST}/oobi/${MS2_PRE}/witness/${WAN_WIT_PREFIX}"
}


create_multisig_aid() {

  echo
  print_yellow "Multisig Config file: ${KERI_DEMO_SCRIPT_DIR}/data/multisig-sample.json"
  echo
  print_yellow "multisig1: Creating Multisig AID with"

  # Follow commands run in parallel
  PID_LIST=()
  kli multisig incept --name multisig1 \
    --alias multisig1 \
    --group multisig \
    --file "${KERI_DEMO_SCRIPT_DIR}/data/multisig-sample.json" &
  PID_LIST+=("$!")
  echo
  print_yellow "multisig2: Creating Multisig AID"

  # Doesn't work, use kli multisig join instead
#  kli multisig incept --name multisig2 \
#    --alias multisig2 \
#    --group multisig \
#    --file "${KERI_DEMO_SCRIPT_DIR}/data/multisig-sample.json" &

  kli multisig join --name multisig2 --auto &
  PID_LIST+=("$!")

  echo
  print_lcyan "Waiting on Multisig AID creation"
  wait "${PID_LIST[@]}"

  echo
  print_yellow "Show multisig AID status for multisig1"
  echo
  kli status --name multisig1 --alias multisig
}


rotate_keys () {
  echo
  print_yellow "Rotating keys prior to multisig"

  kli rotate --name multisig1 \
    --alias multisig1
  kli query --name multisig2 \
    --alias multisig2 \
    --prefix ${MS1_PRE}
  kli rotate --name multisig2 \
    --alias multisig2
  kli query --name multisig1 \
    --alias multisig1 \
    --prefix ${MS2_PRE}

  echo
}


rotate_multisig_key() {
  print_lcyan "Performing multisig rotate for multisig group [multisig1, multisig2]"
  echo
  # smids = Participants with signing authority
  # rmids = Participants with rotation authority
  PID_LIST=()
  kli multisig rotate --name multisig1 \
    --alias multisig \
    --smids "${MS1_PRE}" \
    --smids "${MS2_PRE}" \
    --isith '["1/2", "1/2"]' \
    --nsith '["1/2", "1/2"]' \
    --rmids "${MS1_PRE}" \
    --rmids "${MS2_PRE}"  &
  PID_LIST+=("$!")

  echo
  # Doesn't work, use kli multisig join instead
#  kli multisig rotate --name multisig2 \
#    --alias multisig \
#    --smids ${MS2_PRE} \
#    --smids ${MS1_PRE} \
#    --isith '["1/2", "1/2"]' \
#    --nsith '["1/2", "1/2"]' \
#    --rmids ${MS2_PRE} \
#    --rmids ${MS1_PRE} &

  kli multisig join --name multisig2 --auto &
  PID_LIST+=("$!")

  #kli oobi resolve --name multisig3 \
  #  --oobi-alias multisig \
  #  --oobi "${WIT_HOST}/oobi/${MULTISIG_AID}/witness/${WAN_WIT_PREFIX}"

  #echo 'Run "kli multisig join --name multisig3" in other terminal now'

  wait "${PID_LIST[@]}"

  echo
  print_green "Multisig rotation complete"
  echo

  kli status --name multisig1 --alias multisig
}

multisig_interact() {
  PID_LIST=()

  kli multisig interact --name multisig1 --alias multisig --data '{"d": "elemental"}' &
  PID_LIST+=("$!")

  # Doesn't work, use kli multisig join instead
  #kli multisig interact --name multisig2 --alias multisig --data '{"d": "elemental"}' &

  kli multisig join --name multisig2 --auto &
  PID_LIST+=("$!")

  wait "${PID_LIST[@]}"

  kli status --name multisig1 --alias multisig
}


main() {
  print_red "Cleaning up KERI_HOME: ${KERI_HOME}"
  cleanup

  create_identifiers
  resolve_oobis
  create_multisig_aid
  rotate_keys
  rotate_multisig_key
  multisig_interact

  print_green "Multisig Rotation and Interaction complete"
}

main

