#!/bin/bash -x
export COM_DIAG_DIMINUTO_LOG_MASK=0xfffe
unittest-server -B 4096 -b 1048576 -s 60 -v  & sleep 1
dd if=/dev/urandom bs=1024 count=1048576 iflag=fullblock | unittest-client -B 4096 -v > /dev/null
kill -TERM $!
