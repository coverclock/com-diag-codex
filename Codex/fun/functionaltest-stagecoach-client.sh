#!/bin/bash -x
# Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

ROOT=${1:-"out/host/crt/stagecoach"}

stagecoach -C ${ROOT}/clientcert.pem -K ${ROOT}/clientkey.pem -P ${ROOT} -f cadmium4:stagecoachssl -n :stagecoachclient -c
