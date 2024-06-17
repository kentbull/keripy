#!/bin/bash

# WITNESSES
# To run the following scripts, open another console window and run:
# $ kli witness demo

# EFY7MixHb0so4WFFHw6btOPc5qeeWfPm7v5MJWcdcbyG
MS1=EFY7MixHb0so4WFFHw6btOPc5qeeWfPm7v5MJWcdcbyG
kli init --name multisigj1 --salt 0ACDEyMzQ1Njc4OWxtbm9aBc \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name multisigj1 --alias multisigj1 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-1-sample.json

# EKJ6tNVUGbdaiwx2nWDCFXG-_PY_AzESOcoKlm0kRNP3
MS2=EKJ6tNVUGbdaiwx2nWDCFXG-_PY_AzESOcoKlm0kRNP3
kli init --name multisigj2 --salt 0ACDEyMzQ1Njc4OWdoaWpsaw \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name multisigj2 --alias multisigj2 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-2-sample.json

# EKxxKVNmC3M_u3eDF6Nw6MjRlRx1s_9Y-DV234UtkqAF
MS3=EKxxKVNmC3M_u3eDF6Nw6MjRlRx1s_9Y-DV234UtkqAF
kli init --name multisigj3 --salt 0ADR4R9kW_3ZvbwWGnA5YVah \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --config-dir "${KERI_SCRIPT_DIR}" --config-file demo-witness-oobis
kli incept --name multisigj3 --alias multisigj3\
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-3-sample.json

kli oobi resolve --name multisigj1 --oobi-alias multisigj2 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$MS2/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisigj1 --oobi-alias multisigj3 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$MS3/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisigj2 --oobi-alias multisigj1 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$MS1/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisigj2 --oobi-alias multisigj3 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$MS3/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisigj3 --oobi-alias multisigj2 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$MS2/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha
kli oobi resolve --name multisigj3 --oobi-alias multisigj1 \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --oobi http://127.0.0.1:5642/oobi/$MS1/witness/BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha

PID_LIST=""

kli multisig incept --name multisigj1 --alias multisigj1 --group multisig \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --file ${KERI_DEMO_SCRIPT_DIR}/data/multisig-join-sample.json &
pid=$!
PID_LIST+=" $pid"

kli multisig join --name multisigj2 --passcode "DoB26Fj4x9LboAFWJra17O" --auto &
pid=$!
PID_LIST+=" $pid"

kli multisig join --name multisigj3 --passcode "DoB26Fj4x9LboAFWJra17O" --auto &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

kli status --name multisigj1 --alias multisig --passcode "DoB26Fj4x9LboAFWJra17O"

kli rotate --name multisigj1 --alias multisigj1 --passcode "DoB26Fj4x9LboAFWJra17O"
kli rotate --name multisigj2 --alias multisigj2 --passcode "DoB26Fj4x9LboAFWJra17O"
kli rotate --name multisigj3 --alias multisigj3 --passcode "DoB26Fj4x9LboAFWJra17O"

kli query --name multisigj1 --alias multisigj1 --prefix $MS2 --passcode "DoB26Fj4x9LboAFWJra17O"
kli query --name multisigj1 --alias multisigj1 --prefix $MS3 --passcode "DoB26Fj4x9LboAFWJra17O"
kli query --name multisigj2 --alias multisigj2 --prefix $MS1 --passcode "DoB26Fj4x9LboAFWJra17O"
kli query --name multisigj2 --alias multisigj2 --prefix $MS3 --passcode "DoB26Fj4x9LboAFWJra17O"
kli query --name multisigj3 --alias multisigj3 --prefix $MS1 --passcode "DoB26Fj4x9LboAFWJra17O"
kli query --name multisigj3 --alias multisigj3 --prefix $MS2 --passcode "DoB26Fj4x9LboAFWJra17O"

PID_LIST=""

kli multisig rotate --name multisigj1 --alias multisig \
  --passcode "DoB26Fj4x9LboAFWJra17O" \
  --smids $MS2 --smids $MS1 --smids $MS3 \
  --isith '["1/2", "1/2", "1/2"]' \
  --nsith '["1/2", "1/2", "1/2"]' \
  --rmids $MS2 --rmids $MS1 --rmids $MS3 &
pid=$!
PID_LIST+=" $pid"

kli multisig join --name multisigj2 --passcode "DoB26Fj4x9LboAFWJra17O" --auto &
pid=$!
PID_LIST+=" $pid"

kli multisig join --name multisigj3 --passcode "DoB26Fj4x9LboAFWJra17O" --auto &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

kli status --name multisigj1 --alias multisig --passcode "DoB26Fj4x9LboAFWJra17O"

PID_LIST=""

kli multisig interact --name multisigj1 --alias multisig --passcode "DoB26Fj4x9LboAFWJra17O" --data '{"d": "potato"}' &
pid=$!
PID_LIST+=" $pid"

kli multisig join --name multisigj2 --passcode "DoB26Fj4x9LboAFWJra17O" --auto &
pid=$!
PID_LIST+=" $pid"

kli multisig join --name multisigj3 --passcode "DoB26Fj4x9LboAFWJra17O" --auto &
pid=$!
PID_LIST+=" $pid"

wait $PID_LIST

kli status --name multisigj1 --alias multisig --passcode "DoB26Fj4x9LboAFWJra17O"
