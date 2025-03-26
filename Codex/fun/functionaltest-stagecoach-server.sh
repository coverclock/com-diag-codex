#!/bin/bash -x
# Copyright 2023-2025 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

ROOT=$(readlink -e $(dirname ${0}))
CERT=${1:-"${ROOT}/../crt"}

. ${ROOT}/functionaltest-stagecoach

# This password is only used for testing.
export COM_DIAG_CODEX_SERVER_PASSWORD=st8g3c08ch

. $(readlink -e $(dirname ${0}))/functionaltest-stagecoach

stagecoach -C ${CERT}/stagecoach-servercert.pem -K ${CERT}/stagecoach-serverkey.pem -P ${CERT} -f ${STAGECOACHFAREND}:${STAGECOACHSERVER} -n ${STAGECOACHNEAREND}:${STAGECOACHSSL} -s
