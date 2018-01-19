#!/bin/bash -x
NEAREND=${1:-"49152"}
FAREND=${2:-"localhost:${NEAREND}"}
export COM_DIAG_DIMINUTO_LOG_MASK=0xfffe
unittest-server -n ${NEAREND} -B 4096 -b 1048576 -s 60 -v  & sleep 1
dd if=/dev/urandom bs=8192 count=1048576 iflag=fullblock | time unittest-client -f ${FAREND} -B 4096 -v > /dev/null
kill -TERM $!
