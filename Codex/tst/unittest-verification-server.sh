#!/bin/bash -x

CLIENTS=${1:-"1"}
PERIOD=${2:-"10"}
BUFSIZE=${3:-"512"}
BLOCKSIZE=${4:-"4096"}
BLOCKS=${5:-"1048576"}
NEAREND=${6:-"49242"}
FAREND=${7:-"localhost:${NEAREND}"}
EXPECTED="other.prairiethorn.org"

export COM_DIAG_DIMINUTO_LOG_MASK=0xfffe

unittest-handshake-server -e "${EXPECTED}" -n ${NEAREND} -B ${BUFSIZE} -v  &
SERVER=$!

while [[ ${CLIENTS} -gt 0 ]]; do

    sleep 1
    dd if=/dev/urandom bs=${BLOCKSIZE} count=${BLOCKS} iflag=fullblock | unittest-handshake-client -f ${FAREND} -B ${BUFSIZE} -p ${PERIOD} -v > /dev/null &
    CLIENT="${CLIENT} $!"
    CLIENTS=$(( ${CLIENTS} - 1 ))

done

trap "kill -9 ${SERVER} ${CLIENT} 2> /dev/null" HUP INT TERM EXIT
wait ${CLIENT}
kill -TERM ${SERVER}
wait ${SERVER}
