#!/bin/bash
# Copyright 2025 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex
#
# This unit test is not run by default because I find that valgrind doesn't
# work on some flavors of Linux on some SBCs, even though it installs okay.

PROGRAM=$(basename ${0})

echo "${PROGRAM}: BEGIN" 1>&2

XC=0

BLOCKSIZE=4096
BLOCKS=16

TUNNEL=49128
NEAREND=49129
FAREND=49130

ROOT=$(readlink -e $(dirname ${0}))
CERT="${ROOT}/../crt"

BUFFERSIZE=256
PEAKBYTERATE=256
SUSTAINEDBYTERATE=256
MAXIMUMBURSTSIZE=256

# This password is only used for testing.
export COM_DIAG_CODEX_SERVER_PASSWORD=st8g3c08ch

echo "${PROGRAM}: SERVER" 1>&2

valgrind --show-error-list=yes --leak-check=full stagecoach -i -b ${BUFFERSIZE} -C ${CERT}/stagecoach-servercert.pem -K ${CERT}/stagecoach-serverkey.pem -P ${CERT} -f localhost:${FAREND} -n 0.0.0.0:${TUNNEL} -s &
PIDSERVER=$!
sleep 5

echo "${PROGRAM}: CLIENT 1" 1>&2

valgrind --show-error-list=yes --leak-check=full stagecoach -i -b ${BUFFERSIZE} -C ${CERT}/stagecoach-clientcert.pem -K ${CERT}/stagecoach-clientkey.pem -P ${CERT} -f localhost:${TUNNEL} -n 0.0.0.0:${NEAREND} -c &
PIDCLIENT1=$!
sleep 10

kill ${PIDCLIENT1} || XC=1

echo "${PROGRAM}: CLIENT 2" 1>&2

valgrind --show-error-list=yes --leak-check=full stagecoach -i -b ${BUFFERSIZE} -C ${CERT}/stagecoach-clientcert.pem -K ${CERT}/stagecoach-clientkey.pem -P ${CERT} -f localhost:${TUNNEL} -n 0.0.0.0:${NEAREND} -c &
PIDCLIENT2=$!
sleep 10

kill ${PIDCLIENT2} || XC=2

echo "${PROGRAM}: CLIENT 3" 1>&2

valgrind --show-error-list=yes --leak-check=full stagecoach -i -b ${BUFFERSIZE} -C ${CERT}/stagecoach-clientcert.pem -K ${CERT}/stagecoach-clientkey.pem -P ${CERT} -f localhost:${TUNNEL} -n 0.0.0.0:${NEAREND} -c &
PIDCLIENT3=$!
sleep 10

kill ${PIDCLIENT3} || XC=3

kill ${PIDSERVER} || XC=4

echo "${PROGRAM}: END" 1>&2

exit ${XC}
