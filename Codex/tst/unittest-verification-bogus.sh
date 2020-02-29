#!/bin/bash
# Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

CLIENTS=${1:-"1"}
PERIOD=${2:-"10"}
BUFSIZE=${3:-"512"}
BLOCKSIZE=${4:-"4096"}
BLOCKS=${5:-"1024"}
NEAREND=${6:-"49462"}
FAREND=${7:-"127.0.0.1:${NEAREND}"}
EXPECTED="client.prairiethorn.org"

export COM_DIAG_DIMINUTO_LOG_MASK=0xfffe

CRTPATH="$(realpath $(dirname $0))/../crt"

unittest-handshake-server -e "${EXPECTED}" -n ${NEAREND} -B ${BUFSIZE} &
SERVER=$!

while [[ ${CLIENTS} -gt 0 ]]; do

    sleep 1
    dd if=/dev/urandom bs=${BLOCKSIZE} count=${BLOCKS} iflag=fullblock | unittest-handshake-client -C ${CRTPATH}/bogus.pem -K ${CRTPATH}/bogus.pem -f ${FAREND} -B ${BUFSIZE} -p ${PERIOD} > /dev/null &
    CLIENT="${CLIENT} $!"
    CLIENTS=$(( ${CLIENTS} - 1 ))

done

trap "kill -9 ${SERVER} ${CLIENT} 2> /dev/null" HUP INT TERM EXIT
wait ${CLIENT}
kill -TERM ${SERVER}
wait ${SERVER}

