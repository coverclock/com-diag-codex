#!/bin/bash 
# Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

# See also: bin/unittest-time.awk that that extracts data
#           from the resulting log file and formats it
#           into a CSV file suitable for Excel.

# The sleep delays are to accomodate the fact that
# I can't quite seem to set the REUSE socket option
# in OpenSSL.

FIRST=1
LAST=1048576

if true; then
    BLOCKS=${FIRST}
    while [[ ${BLOCKS} -le ${LAST} ]]; do
        echo unittest-time-control ${BLOCKS}
        unittest-time-control ${BLOCKS}
        BLOCKS=$(( ${BLOCKS} * 2 ))
	if [[ ${BLOCKS} -le ${LAST} ]]; then
            sleep 10
	fi
    done
fi

if true; then
    BLOCKS=${FIRST}
    while [[ ${BLOCKS} -le ${LAST} ]]; do
        echo unittest-time-core ${BLOCKS}
        unittest-time-core ${BLOCKS}
        BLOCKS=$(( ${BLOCKS} * 2 ))
	if [[ ${BLOCKS} -le ${LAST} ]]; then
            sleep 300
	fi
    done
fi

exit 0
