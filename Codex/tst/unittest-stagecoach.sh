#!/bin/bash
# Copyright 2025 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

PROGRAM=$(basename ${0})
CLIENTS=${1:-"3"}
PERIOD=${2:-"10"}
BUFSIZE=${3:-"512"}
BLOCKSIZE=${4:-"4096"}
BLOCKS=${5:-"1024"}
NEAREND=${6:-"49123"}
FAREND=${7:-"127.0.0.1:${NEAREND}"}

FILE1=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILE1-XXXXXXXXXX.dat)
FILE2=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILE2-XXXXXXXXXX.dat)
FILEA=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILEA-XXXXXXXXXX.dat)
FILEB=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILEB-XXXXXXXXXX.dat)

trap "rm -f ${FILE1} ${FILE2} ${FILEA} ${FILEB} 2> /dev/null" HUP INT TERM

dd if=/dev/urandom bs=${BLOCKSIZE} count=${BLOCKS} iflag=fullblock of=${FILE1}
dd if=/dev/urandom bs=${BLOCKSIZE} count=${BLOCKS} iflag=fullblock of=${FILE2}
