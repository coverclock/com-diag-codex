#!/bin/bash -x
# Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

ROOT=${1:-"out/host/crt/stagecoach"}

. $(readlink -e $(dirname ${0}))/functionaltest-stagecoach

stagecoach -C ${ROOT}/clientcert.pem -K ${ROOT}/clientkey.pem -P ${ROOT}/.. -f ${STAGECOACHFAREND}:${STAGECOACHSSL} -n ${STAGECOACHNEAREND}:${STAGECOACHCLIENT} -c
