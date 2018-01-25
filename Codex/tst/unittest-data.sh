#!/bin/bash -x
NEAREND=${1:-"49152"}
FAREND=${2:-"localhost:${NEAREND}"}
export COM_DIAG_DIMINUTO_LOG_MASK=0xfffe
unittest-server -n ${NEAREND} -B 4096 -b 1048576 -s 60 -v  &
SERVER=$!
sleep 1
dd if=/dev/urandom bs=4096 count=1048576 iflag=fullblock | unittest-client -f ${FAREND} -B 4096 -p 5 -v > /dev/null &
CLIENT1=$!
sleep 1
dd if=/dev/urandom bs=4096 count=1048576 iflag=fullblock | unittest-client -f ${FAREND} -B 4096 -p 5 -v > /dev/null &
CLIENT2=$!
sleep 1
dd if=/dev/urandom bs=4096 count=1048576 iflag=fullblock | unittest-client -f ${FAREND} -B 4096 -p 5 -v > /dev/null &
CLIENT3=$!
trap "kill -9 ${SERVER} ${CLIENT1} ${CLIENT2} ${CLIENT3} 2> /dev/null" HUP INT TERM EXIT
wait ${CLIENT1} ${CLIENT2} ${CLIENT3}
kill -TERM ${SERVER}
