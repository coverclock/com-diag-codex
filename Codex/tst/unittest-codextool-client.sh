#!/bin/bash
# Copyright 2025 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex
#

################################################################################
# BEGIN
################################################################################

PROGRAM=$(basename ${0})

echo "${PROGRAM}: BEGIN" 1>&2

XC=0

BLOCKSIZE=4096
BLOCKS=16

TUNNEL=49127

ROOT=$(readlink -e $(dirname ${0}))
CERT="${ROOT}/../crt"

BUFFERSIZE=256

# This password is only used for testing.
export COM_DIAG_CODEX_SERVER_PASSWORD=c0d3xt001

################################################################################
# FILES
################################################################################

echo "${PROGRAM}: FILES" 1>&2

FILECLIENTSOURCE=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILECLIENTSOURCE-XXXXXXXXXX.dat)
FILECLIENTSINK=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILECLIENTSINK-XXXXXXXXXX.dat)

dd if=/dev/urandom bs=${BLOCKSIZE} count=${BLOCKS} iflag=fullblock of=${FILECLIENTSOURCE}

FILESERVERSINK=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILESERVERSINK-XXXXXXXXXX.dat)

FILES="${FILECLIENTSOURCE} ${FILECLIENTSINK} ${FILESERVERSINK}"

ls -l ${FILES}

################################################################################
# PROCESSES
################################################################################

echo "${PROGRAM}: PROCESSES" 1>&2

codextool -b ${BUFFERSIZE} -C ${CERT}/codextool-servercert.pem -K ${CERT}/codextool-serverkey.pem -P ${CERT} -n 0.0.0.0:${TUNNEL} < /dev/null > ${FILESERVERSINK} &
PIDSERVER=$!
sleep 5

codextool -b ${BUFFERSIZE} -C ${CERT}/codextool-clientcert.pem -K ${CERT}/codextool-clientkey.pem -P ${CERT} -f localhost:${TUNNEL} < ${FILECLIENTSOURCE} > ${FILECLIENTSINK} &
PIDCLIENT=$!
sleep 5

PIDS="${PIDSERVER} ${PIDCLIENT}"

ps -f ${PIDS}

################################################################################
# EXECUTE
################################################################################

echo "${PROGRAM}: EXECUTE" 1>&2

trap "ps -f ${PIDS} 2> /dev/null; kill -9 ${PIDS} 2> /dev/null; ls -l ${FILES} 2> /dev/null; rm -f ${FILES} 2> /dev/null" HUP INT TERM

wait ${PIDCLIENT}

sleep 5

ps -f ${PIDS}

kill ${PIDS} 2> /dev/null

################################################################################
# RESULTS
################################################################################

echo "${PROGRAM}: RESULTS" 1>&2

ls -l ${FILECLIENTSOURCE}

dump ${FILECLIENTSOURCE} | head

ls -l ${FILESERVERSINK}

dump ${FILESERVERSINK} | head

diff ${FILECLIENTSOURCE} ${FILESERVERSINK} || XC=$((${XC} + 1)) && rm -f ${FILECLIENTSOURCE} ${FILESERVERSINK}

ls -l ${FILECLIENTSINK}

dump ${FILECLIENTSINK} | head

test -s ${FILECLIENTSINK} && XC=$((${XC} + 1)) || rm -f ${FILECLIENTSINK}

################################################################################
# END
################################################################################

echo "${PROGRAM}: END ${XC}" 1>&2

exit ${XC}
