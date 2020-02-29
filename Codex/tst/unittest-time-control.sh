#!/bin/bash
# Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

BLOCKS=${1:-1048576}
BUFSIZE=${2:-512}
CLIENTS=1
PERIOD=10
BLOCKSIZE=4096
NEAREND=49582
FAREND="127.0.0.1:${NEAREND}"

export COM_DIAG_DIMINUTO_LOG_MASK=0xfffe

time unittest-control-server -n ${NEAREND} -B ${BUFSIZE} &
SERVER=$!

while [[ ${CLIENTS} -gt 0 ]]; do

    sleep 1
    dd if=/dev/urandom bs=${BLOCKSIZE} count=${BLOCKS} iflag=fullblock | unittest-control-client -f ${FAREND} -B ${BUFSIZE} -p ${PERIOD} > /dev/null &
    CLIENT="${CLIENT} $!"
    CLIENTS=$(( ${CLIENTS} - 1 ))

done

trap "kill -9 ${SERVER} ${CLIENT} 2> /dev/null" HUP INT TERM EXIT
wait ${CLIENT}
pkill -f -TERM unittest-control-server
wait ${SERVER}
echo "blocks	${BLOCKS}"
echo "blksize	${BLOCKSIZE}"
echo "bytes	$(( ${BLOCKS} * ${BLOCKSIZE} ))"
echo "bufsize	${BUFSIZE}"
