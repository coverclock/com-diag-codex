#!/bin/bash
# Copyright 2018-2025 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

PROGRAM=$(basename ${0})
BLOCKS=${1:-1048576}
BUFSIZE=${2:-512}
CLIENTS=1
PERIOD=10
BLOCKSIZE=4096
NEAREND=50002
FAREND="127.0.0.1:${NEAREND}"

time functionaltest-core-server -n ${NEAREND} -B ${BUFSIZE} &
SERVER=$!

while [[ ${CLIENTS} -gt 0 ]]; do

    sleep 1
    dd if=/dev/urandom bs=${BLOCKSIZE} count=${BLOCKS} iflag=fullblock | functionaltest-core-client -f ${FAREND} -B ${BUFSIZE} -p ${PERIOD} > /dev/null &
    CLIENT="${CLIENT} $!"
    CLIENTS=$(( ${CLIENTS} - 1 ))

done

trap "kill -9 ${SERVER} ${CLIENT} 2> /dev/null" HUP INT TERM EXIT

CEXIT=0
for CC in ${CLIENT}; do
    wait ${CC}
    SS=$?
    CEXIT=$(( ${CEXIT} + ${SS} ))
done
kill -TERM ${SERVER}
wait ${SERVER}
SEXIT=$?

echo "${PROGRAM}: blocks    ${BLOCKS}" 1>&2
echo "${PROGRAM}: blksize   ${BLOCKSIZE}" 1>&2
echo "${PROGRAM}: bytes     $(( ${BLOCKS} * ${BLOCKSIZE} ))" 1>&2
echo "${PROGRAM}: bufsize   ${BUFSIZE}" 1>&2

echo "${PROGRAM}: END ${CEXIT}+${SEXIT}" 1>&2
exit $(( ${CEXIT} + ${SEXIT} ))
