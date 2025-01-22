#!/bin/bash
# Copyright 2018-2025 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

PROGRAM=$(basename ${0})
CLIENTS=${1:-"3"}
EXPECTED=$(hostname)
FAREND=${2:-"${EXPECTED}:49302"}
PERIOD=${3:-"10"}
BUFSIZE=${4:-"512"}
BLOCKSIZE=${5:-"4096"}
BLOCKS=${6:-"1048576"}

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
