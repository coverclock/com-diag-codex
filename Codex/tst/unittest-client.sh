#!/bin/bash
# Copyright 2018-2025 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

PROGRAM=$(basename ${0})
CLIENTS=${1:-"3"}
EXPECTED=$(hostname -s)
NEAREND=${2:-"49100"}
FAREND=${3:-"${EXPECTED}:${NEAREND}"}
PERIOD=${4:-"10"}
BUFSIZE=${5:-"512"}
BLOCKSIZE=${6:-"4096"}
BLOCKS=${7:-"1048576"}

while [[ ${CLIENTS} -gt 0 ]]; do

    dd if=/dev/urandom bs=${BLOCKSIZE} count=${BLOCKS} iflag=fullblock | functionaltest-handshake-client -e "${EXPECTED}" -f ${FAREND} -B ${BUFSIZE} -p ${PERIOD} > /dev/null &
    CLIENT="${CLIENT} $!"
    CLIENTS=$(( ${CLIENTS} - 1 ))

done

trap "kill -9 ${CLIENT} 2> /dev/null" HUP INT TERM EXIT

CEXIT=0
for CC in ${CLIENT}; do
    wait ${CC}
    SS=$?
    CEXIT=$(( ${CEXIT} + ${SS} ))
done

echo "${PROGRAM}: END ${CEXIT}" 1>&2
exit ${CEXIT}
