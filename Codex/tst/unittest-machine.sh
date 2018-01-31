#!/bin/bash -x

NEAREND=${1:-"49154"}
FAREND=${2:-"localhost:${NEAREND}"}
BUFSIZE=${3:-"4096"}
PERIOD=${4:-"5"}
BLOCKS=${5:-"1048576"}

export COM_DIAG_DIMINUTO_LOG_MASK=0xfffe

unittest-machine-server -n ${NEAREND} -B ${BUFSIZE} -v  &
SERVER=$!

sleep 1
dd if=/dev/urandom bs=${BUFSIZE} count=${BLOCKS} iflag=fullblock | unittest-machine-client -f ${FAREND} -B ${BUFSIZE} -p ${PERIOD} -v > /dev/null &
CLIENT1=$!

sleep 1
dd if=/dev/urandom bs=${BUFSIZE} count=${BLOCKS} iflag=fullblock | unittest-machine-client -f ${FAREND} -B ${BUFSIZE} -p ${PERIOD} -v > /dev/null &
CLIENT2=$!

sleep 1
dd if=/dev/urandom bs=${BUFSIZE} count=${BLOCKS} iflag=fullblock | unittest-machine-client -f ${FAREND} -B ${BUFSIZE} -p ${PERIOD} -v > /dev/null &
CLIENT3=$!

trap "kill -9 ${SERVER} ${CLIENT1} ${CLIENT2} ${CLIENT3} 2> /dev/null" HUP INT TERM EXIT
wait ${CLIENT1} ${CLIENT2} ${CLIENT3}
kill -TERM ${SERVER}
wait ${SERVER}
