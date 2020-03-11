#!/bin/bash
# Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

NEAREND=${1:-"49302"}
BUFSIZE=${2:-"512"}
EXPECTED="client.prairiethorn.org"

export COM_DIAG_DIMINUTO_LOG_MASK=0xfffe

exec functionaltest-handshake-server -e "${EXPECTED}" -n ${NEAREND} -B ${BUFSIZE}
