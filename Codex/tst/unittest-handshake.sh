#!/bin/bash
# Copyright 2018-2025 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

PROGRAM=$(basename ${0})
CLIENTS=${1:-"3"}
PERIOD=${2:-"10"}
BUFSIZE=${3:-"512"}
BLOCKSIZE=${4:-"4096"}
BLOCKS=${5:-"1048576"}
NEAREND=${6:-"49107"}
EXPECTED="127.0.0.1"
FAREND=${7:-"${EXPECTED}:${NEAREND}"}

CRLPATH="$(realpath $(dirname $0))/../crl"
CRTPATH="$(realpath $(dirname $0))/../crt"

functionaltest-handshake-server -n ${NEAREND} -B ${BUFSIZE} -C ${CRTPATH}/server.pem -D ${CRTPATH}/dh.pem -K ${CRTPATH}/server.pem -R "" -P ${CRTPATH} -L ${CRLPATH}/crl.txt &
SERVER=$!

while [[ ${CLIENTS} -gt 0 ]]; do

    sleep 1
    dd if=/dev/urandom bs=${BLOCKSIZE} count=${BLOCKS} iflag=fullblock | functionaltest-handshake-client -e "${EXPECTED}" -f ${FAREND} -B ${BUFSIZE} -p ${PERIOD} -C ${CRTPATH}/client.pem -D ${CRTPATH}/dh.pem -K ${CRTPATH}/client.pem -R ${CRTPATH}/root.pem -P "" -L ${CRLPATH}/crl.txt > /dev/null &
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

echo "${PROGRAM}: END ${CEXIT}+${SEXIT}" 1>&2
exit $(( ${CEXIT} + ${SEXIT} ))
