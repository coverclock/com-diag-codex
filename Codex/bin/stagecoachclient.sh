#!/bin/bash -x
# Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex
# USAGE: stagecoachclient [ -x ]
#
# Use the stagecoach -x option to cause this to run as a daemon.
#
# IMPORTANT SAFETY TIP: The certs and keys used in this script are
# *not* built by default by the Codex "all" make target. Use the
# "stagecoach" make target to generate them.

ROOT=$(readlink -e $(dirname ${0}))
DAMN=${1:-"-c"}
CERT=${2:-${ROOT}/../crt/stagecoach}

. ${ROOT}/stagecoach

exec coreable stagecoach -C ${CERT}/clientcert.pem -K ${CERT}/clientkey.pem -P ${CERT}/.. -f ${STAGECOACH_CLIENT_FAREND} -n ${STAGECOACH_CLIENT_NEAREND} -c ${DAMN}
