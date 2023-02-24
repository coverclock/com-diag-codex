#!/bin/bash -x
# Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex
# USAGE: stagecoachclient [ -x ]

ROOT=$(readlink -e $(dirname ${0}))
DAMN=${1:-"-c"}
CERT=${2:-${ROOT}/../crt/stagecoach}

. ${ROOT}/stagecoach

exec coreable stagecoach -C ${CERT}/clientcert.pem -K ${CERT}/clientkey.pem -P ${CERT}/.. -f ${STAGECOACH_CLIENT_FAREND} -n ${STAGECOACH_CLIENT_NEAREND} -c ${DAMN}
