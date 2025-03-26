#!/bin/bash -x
# Copyright 2023-2025 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex
# USAGE: stagecoachclient [ -x ]
# Use the stagecoach -x option to cause this to run as a daemon.

ROOT=$(readlink -e $(dirname ${0}))
DEMN=${1:-"-c"}
CERT=${2:-${ROOT}/../crt}

. ${ROOT}/stagecoachdefinitions

exec coreable stagecoach -C ${CERT}/stagecoach-clientcert.pem -K ${CERT}/stagecoach-clientkey.pem -P ${CERT} -f ${STAGECOACH_CLIENT_FAREND} -n ${STAGECOACH_CLIENT_NEAREND} -c ${DEMN}
