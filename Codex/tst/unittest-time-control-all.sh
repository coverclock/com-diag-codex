#!/bin/bash 
# Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

# See also: bin/unittest-time.awk that that extracts data
#           from the resulting log file and formats it
#           into a CSV file suitable for Excel.

# The short sleep delay is so I can peruse the results before it
# moves onto the next test case.

FIRST=1
LAST=1048576

LOW=64
HIGH=4096

BLOCKS=${FIRST}
while [[ ${BLOCKS} -le ${LAST} ]]; do
    BUFFER=${LOW}
    while [[ ${BUFFER} -le ${HIGH} ]]; do
        echo unittest-time-control ${BLOCKS} ${BUFFER}
        unittest-time-control ${BLOCKS} ${BUFFER}
        BUFFER=$(( ${BUFFER} * 2 ))
        sleep 10
    done
    BLOCKS=$(( ${BLOCKS} * 2 ))
done

exit 0
