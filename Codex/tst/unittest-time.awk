#!/usr/bin/awk
# Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex
BEGIN			{ print "TEST,REAL,USER,SYSTEM,TOTAL,BLOCKS,BLOCKSIZE,BYTES,BUFFER"; }
#               { print $0; }
/^unittest/		{ TEST=$1; }
/^real\t/		{ split($2,RR,/[ms]/); REAL=(RR[1]*60)+RR[2]; }
/^user\t/		{ split($2,UU,/[ms]/); USER=(UU[1]*60)+UU[2]; }
/^sys\t/		{ split($2,SS,/[ms]/); SYSTEM=(SS[1]*60)+SS[2]; TOTAL=USER+SYSTEM; }
/^blocks\t/		{ BLOCKS=$2; }
/^blksize\t/	{ BLOCKSIZE=$2; }
/^bytes\t/		{ BYTES=$2; }
/^bufsize\t/    { BUFFER=$2; print "\""TEST"\","REAL","USER","SYSTEM","TOTAL","BLOCKS","BLOCKSIZE","BYTES","BUFFER; }
