#!/bin/bash -x

CLIENTS=${1:-"1"}
PERIOD=${2:-"10"}
BUFSIZE=${3:-"512"}
BLOCKSIZE=${4:-"4096"}
BLOCKS=${5:-"1048576"}
NEAREND=${6:-"49462"}
FAREND=${7:-"localhost:${NEAREND}"}
EXPECTED="client.prairiethorn.org"

export COM_DIAG_DIMINUTO_LOG_MASK=0xffff

unittest-handshake-server -e "${EXPECTED}" -n ${NEAREND} -B ${BUFSIZE} -v  &
SERVER=$!

export COM_DIAG_DIMINUTO_LOG_MASK=0xfffe

while [[ ${CLIENTS} -gt 0 ]]; do

    sleep 1
    dd if=/dev/urandom bs=${BLOCKSIZE} count=${BLOCKS} iflag=fullblock | unittest-handshake-client -C out/host/crt/bogus.pem -K out/host/crt/bogus.pem -f ${FAREND} -B ${BUFSIZE} -p ${PERIOD} -v > /dev/null &
    CLIENT="${CLIENT} $!"
    CLIENTS=$(( ${CLIENTS} - 1 ))

done

trap "kill -9 ${SERVER} ${CLIENT} 2> /dev/null" HUP INT TERM EXIT
wait ${CLIENT}
kill -TERM ${SERVER}
wait ${SERVER}

