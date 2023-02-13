#!/bin/bash -x
# Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

ROOT=${1:-"out/host/crt/stagecoach"}

export COM_DIAG_CODEX_SERVER_PASSWORD=st8g3c08ch

# Note that the use of the IPv4 "unspecified" address for the near end
# SSL server end point serves two purposes: it forces Diminuto to choose
# IPv4 instead of the default of IPv6, and serves as a wild card for the
# socket binding address. Using "localhost" or "localhost4" will prevent
# remote clients from connecting.

stagecoach -C ${ROOT}/servercert.pem -K ${ROOT}/serverkey.pem -P ${ROOT}/.. -f cadmium4:stagecoachserver -n 0.0.0.0:stagecoachssl -s
