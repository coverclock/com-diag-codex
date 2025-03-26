#!/bin/bash
# Copyright 2025 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

################################################################################

PROGRAM=$(basename ${0})
BLOCKSIZE=${1:-"4096"}
BLOCKS=${2:-"4096"}
TUNNEL=${3:-"49123"}
NEAREND=${4:-"49124"}
FAREND=${5:-"49125"}
ROOT=$(readlink -e $(dirname ${0}))
CERT=${6:-${ROOT}/../crt}

XC=0

export COM_DIAG_CODEX_SERVER_PASSWORD=st8g3c08ch

################################################################################

FILE1=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILE1-XXXXXXXXXX.dat)
FILE2=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILE2-XXXXXXXXXX.dat)

dd if=/dev/urandom bs=${BLOCKSIZE} count=${BLOCKS} iflag=fullblock of=${FILE1}
dd if=/dev/urandom bs=${BLOCKSIZE} count=${BLOCKS} iflag=fullblock of=${FILE2}

ls -l ${FILE1} ${FILE2}

FILEA=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILEA-XXXXXXXXXX.dat)
FILEB=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILEB-XXXXXXXXXX.dat)

ls -l ${FILEA} ${FILEB}

################################################################################

SNEAREND=0.0.0.0:${TUNNEL}
SFAREND=localhost:${FAREND}

stagecoach -C ${CERT}/stagecoach-servercert.pem -K ${CERT}/stagecoach-serverkey.pem -P ${CERT} -f ${SFAREND} -n ${SNEAREND} -s &
PIDSERVER=$!
sleep 2

ps -ef ${PIDSERVER}

CNEAREND=0.0.0.0:${NEAREND}
CFAREND=localhost:${TUNNEL}

stagecoach -C ${CERT}/stagecoach-clientcert.pem -K ${CERT}/stagecoach-clientkey.pem -P ${CERT} -f ${CFAREND} -n ${CNEAREND} -c &
PIDCLIENT=$!
sleep 2

ps -ef ${PIDCLIENT}

################################################################################

trap "kill -9 ${PIDCLIENT} ${PIDSERVER} 2> /dev/null; rm -f ${FILE1} ${FILE2} ${FILEA} ${FILEB}" HUP INT TERM

################################################################################

kill ${PIDCLIENT} ${PIDSERVER} 2> /dev/null

################################################################################

diff ${FILE1} ${FILEA} || XC=$((${XC} + 1))

diff ${FILE2} ${FILEB} || XC=$((${XC} + 1))

rm ${FILE1} ${FILE2} ${FILEA} ${FILEB}

################################################################################

exit ${XC}
