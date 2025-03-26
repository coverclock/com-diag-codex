#!/bin/bash -x
# Copyright 2023-2025 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

ROOT=$(readlink -e $(dirname ${0}))
CERT=${1:-"${ROOT}/../crt"}

. ${ROOT}/functionaltest-stagecoach

stagecoach -C ${CERT}/stagecoach-clientcert.pem -K ${CERT}/stagecoach-clientkey.pem -P ${CERT} -f ${STAGECOACHFAREND}:${STAGECOACHSSL} -n ${STAGECOACHNEAREND}:${STAGECOACHCLIENT} -c
