#!/bin/bash -x
# Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex
# USAGE: stagecoachserver [ -x ]
#
# Use the stegecoach -x option to cause this to run as a daemon.
#
# IMPORTANT SAFETY TIP: The certs and keys used in this script are
# *not* built by default by the Codex "all" make target. Use the
# "stagecoach" make target to generate them.

ROOT=$(readlink -e $(dirname ${0}))
DAMN=${1:-"-s"}
CERT=${2:-${ROOT}/../crt/stagecoach}

. ${ROOT}/stagecoach

export COM_DIAG_CODEX_SERVER_PASSWORD=st8g3c08ch

exec coreable stagecoach -C ${CERT}/servercert.pem -K ${CERT}/serverkey.pem -P ${CERT}/.. -f ${STAGECOACH_SERVER_FAREND} -n ${STAGECOACH_SERVER_NEAREND} -s ${DAMN}
