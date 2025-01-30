#!/bin/bash
# Copyright 2018-2025 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

NEAREND=${1:-"49114"}
BUFSIZE=${2:-"512"}
EXPECTED="client.prairiethorn.org"

exec functionaltest-handshake-server -e "${EXPECTED}" -n ${NEAREND} -B ${BUFSIZE}
