#!/bin/bash 
# Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

FIRST=1
LAST=1048576

if false; then
    BLOCKS=${FIRST}
    while [[ ${BLOCKS} -le ${LAST} ]]; do
        echo unittest-time-control ${BLOCKS}
        unittest-time-control ${BLOCKS}
        sleep 10
        BLOCKS=$(( ${BLOCKS} * 2 ))
    done
fi

if true; then
    BLOCKS=${FIRST}
    while [[ ${BLOCKS} -le ${LAST} ]]; do
        echo unittest-time-core ${BLOCKS}
        unittest-time-core ${BLOCKS}
        sleep 300
        BLOCKS=$(( ${BLOCKS} * 2 ))
    done
fi

exit 0
