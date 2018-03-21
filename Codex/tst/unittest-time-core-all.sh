#!/bin/bash 
# Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

# See also: bin/unittest-time.awk that that extracts data
#           from the resulting log file and formats it
#           into a CSV file suitable for Excel.

# The long sleep delay is because I can't quite seem to figure
# out how to set the REUSE socket option in OpenSSL.

FIRST=1
LAST=1048576

LOW=64
HIGH=4096

BLOCKS=${FIRST}
while [[ ${BLOCKS} -le ${LAST} ]]; do
    BUFFER=${LOW}
    while [[ ${BUFFER} -le ${HIGH} ]]; do
        echo unittest-time-core ${BLOCKS} ${BUFFER}
        unittest-time-core ${BLOCKS} ${BUFFER}
        BUFFER=$(( ${BUFFER} * 2 ))
        sleep 300
    done
    BLOCKS=$(( ${BLOCKS} * 2 ))
done

exit 0
