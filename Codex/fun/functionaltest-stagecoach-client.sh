#!/bin/bash -x
# Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

ROOT=${1:-"out/host/crt/stagecoach"}

# Note that the use of the IPv4 "unspecified" address for the near end
# UDP client end point serves two purposes: it forces Diminuto to choose
# IPv4 instead of the default of IPv6, and serves as a wild card for the
# socket binding address. Using "localhost" or "localhost4" will prevent
# remote UDP sources from connecting.

stagecoach -C ${ROOT}/clientcert.pem -K ${ROOT}/clientkey.pem -P ${ROOT}/.. -f cadmium4:stagecoachssl -n 0.0.0.0:stagecoachclient -c
