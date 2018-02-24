#!/bin/bash
# Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

# "Bronze"   
# Raspberry Pi 2 Model B (32-bit ARM)  
# Broadcom BCM2836 Cortex-A7 ARMv7 @ 900MHz x 4  
# Raspbian GNU/Linux 8.0 "jessie"  
# Linux 4.4.34  
# gcc 4.9.2  
# OpenSSL 1.0.1t  3 May 2016

CLIENTS=${1:-"3"}
FAREND=${2:-"nickel:49222"}
PERIOD=${3:-"10"}
BUFSIZE=${4:-"512"}
BLOCKSIZE=${5:-"4096"}
BLOCKS=${6:-"1048576"}

export COM_DIAG_DIMINUTO_LOG_MASK=0xfffe

while [[ ${CLIENTS} -gt 0 ]]; do

    dd if=/dev/urandom bs=${BLOCKSIZE} count=${BLOCKS} iflag=fullblock | unittest-handshake-client -f ${FAREND} -B ${BUFSIZE} -p ${PERIOD} -v > /dev/null &
    CLIENT="${CLIENT} $!"
    CLIENTS=$(( ${CLIENTS} - 1 ))

done

trap "kill -9 ${CLIENT} 2> /dev/null" HUP INT TERM EXIT
wait ${CLIENT}