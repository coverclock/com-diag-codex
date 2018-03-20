#!/bin/bash
# Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

BLOCKS=${1:-"1048576"}
CLIENTS=1
PERIOD=10
BUFSIZE=512
BLOCKSIZE=4096
NEAREND=50002
FAREND="localhost:${NEAREND}"

export COM_DIAG_DIMINUTO_LOG_MASK=0xfffe

time unittest-core-server -n ${NEAREND} -B ${BUFSIZE} &
SERVER=$!

while [[ ${CLIENTS} -gt 0 ]]; do

    sleep 1
    dd if=/dev/urandom bs=${BLOCKSIZE} count=${BLOCKS} iflag=fullblock | unittest-core-client -f ${FAREND} -B ${BUFSIZE} -p ${PERIOD} > /dev/null &
    CLIENT="${CLIENT} $!"
    CLIENTS=$(( ${CLIENTS} - 1 ))

done

trap "kill -9 ${SERVER} ${CLIENT} 2> /dev/null" HUP INT TERM EXIT
wait ${CLIENT}
pkill -f -TERM unittest-core-server
wait ${SERVER}
echo "blocks	${BLOCKS}"
echo "blksize	${BLOCKSIZE}"
echo "bytes	$(( ${BLOCKS} * ${BLOCKSIZE} ))"
