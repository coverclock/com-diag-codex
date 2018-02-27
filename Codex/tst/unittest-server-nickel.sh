#!/bin/bash
# Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

# "Nickel"    
# Intel NUC5i7RYH    
# Intel Core i7-5557U @ 3.10GHz x 8    
# Ubuntu 16.04.3 LTS "xenial"    
# Linux 4.10.0    
# gcc 5.4.0    
# OpenSSL 1.0.2g  1 Mar 2016

NEAREND=${1:-"49302"}
BUFSIZE=${2:-"512"}

export COM_DIAG_DIMINUTO_LOG_MASK=0xfffe

exec unittest-handshake-server -n ${NEAREND} -B ${BUFSIZE}
