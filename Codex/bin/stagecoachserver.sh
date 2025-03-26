#!/bin/bash -x
# Copyright 2023-2025 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex
# USAGE: stagecoachserver [ -x ]
# Use the stegecoach -x option to cause this to run as a daemon.

ROOT=$(readlink -e $(dirname ${0}))
DEMN=${1:-"-s"}
CERT=${2:-${ROOT}/../crt}

. ${ROOT}/stagecoachdefinitions

exec coreable stagecoach -C ${CERT}/stagecoach-servercert.pem -K ${CERT}/stagecoach-serverkey.pem -P ${CERT} -f ${STAGECOACH_SERVER_FAREND} -n ${STAGECOACH_SERVER_NEAREND} -s ${DEMN}
