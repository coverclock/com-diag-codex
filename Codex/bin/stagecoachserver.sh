#!/bin/bash -x
# Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex
# USAGE: stagecoachserver [ -x ]

ROOT=$(readlink -e $(dirname ${0}))
DAMN=${1:-"-s"}
CERT=${2:-${ROOT}/../crt/stagecoach}

. ${ROOT}/stagecoach

if [ "$COM_DIAG_CODEX_SERVER_PASSWORD" = "" ]; then
    export COM_DIAG_CODEX_SERVER_PASSWORD=st8g3c08ch
fi

exec coreable stagecoach -C ${CERT}/servercert.pem -K ${CERT}/serverkey.pem -P ${CERT}/.. -f ${STAGECOACH_SERVER_FAREND} -n ${STAGECOACH_SERVER_NEAREND} -s ${DAMN}
