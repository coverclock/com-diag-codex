#!/bin/bash -x
# Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

ROOT=${1:-"out/host/crt/stagecoach"}

export COM_DIAG_CODEX_SERVER_PASSWORD=st8g3c08ch

. $(readlink -e $(dirname ${0}))/stagecoach

stagecoach -C ${ROOT}/servercert.pem -K ${ROOT}/serverkey.pem -P ${ROOT}/.. -f ${STAGECOACH_SERVER_FAREND} -n ${STAGECOACH_SERVER_NEAREND} -s
