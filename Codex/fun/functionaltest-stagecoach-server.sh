#!/bin/bash -x
# Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

ROOT=${1:-"out/host/crt/stagecoach"}

export COM_DIAG_CODEX_SERVER_PASSWORD=st8g3c08ch

# If no host is specified for the nearendpoint, Diminuto assumes IPv6 by default.
# We don't technically need a host for the nearendpoint (it will be the
# service port for the client, and an ephemeral for the server, since both
# are acting as proxies). But using a host name like "localhost", "localhost4",
# "localhost6", etc. causes Diminuto to choose a specific protocol rather than
# the default. I recommend it, but don't require it.

stagecoach -C ${ROOT}/servercert.pem -K ${ROOT}/serverkey.pem -P ${ROOT}/.. -f cadmium4:stagecoachserver -n localhost:stagecoachssl -s
