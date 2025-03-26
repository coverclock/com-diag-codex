#!/bin/bash
# Copyright 2025 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

# stagcoach is a tool built on top of the Codex and Diminuto libraries,
# which is used support of gpstool that is built on top of the Hazer and
# Diminuto libraries. gpstool can transmit a variety of information -
# NMEA sentences, RTK updates, or CSV PNT information, via UDP datagrams to
# a remote system, which may also be running gpstool. This facility is used,
# for example, with Differential GNSS systems, remote tracking applications,
# etc. stagecoach is a go-between tool that receives UDP datagrams, tunnels
# them through an SSL tunnel, then forwards them via UDP to the receiver.
#
# Why not just use SSL to begin with? Because communication channels that
# use TCP, like SSL, or even those that use third-party mechanisms like
# Google's QUIC (which basically implements all of TCP's mechanisms in
# user space), mess up the real-time nature of the UDP datagrams and make
# the NMEA, RTK, PNT etc. data a lot less useful.
#
# A stagecoach process in server mode acts as a proxy on the nearend for the
# farend server for the producer, and another as the proxy on the farend for
# the nearend client for the consumer.
#
#                     proxy            proxy
# PRODUCER <---UDP--> SERVER <==SSL==> CLIENT <---UDP--> CONSUMER
# nearend             nearend          farend            farend
#  |                   |                |                 |
# gpstool             stagecoach       stagecoach        gpstool
# rover                                                  base

################################################################################

ROOT=$(readlink -e $(dirname ${0}))

PROGRAM=$(basename ${0})
BLOCKSIZE=${1:-"4096"}
BLOCKS=${2:-"4096"}
TUNNEL=${3:-"49123"}
NEAREND=${4:-"49124"}
FAREND=${5:-"49125"}
CERT=${6:-${ROOT}/../crt}

XC=0

# This password is only used for testing.
export COM_DIAG_CODEX_SERVER_PASSWORD=st8g3c08ch

################################################################################

FILE1=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILE1-XXXXXXXXXX.dat)
FILE2=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILE2-XXXXXXXXXX.dat)

dd if=/dev/urandom bs=${BLOCKSIZE} count=${BLOCKS} iflag=fullblock of=${FILE1}
dd if=/dev/urandom bs=${BLOCKSIZE} count=${BLOCKS} iflag=fullblock of=${FILE2}

ls -l ${FILE1} ${FILE2}

FILEA=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILEA-XXXXXXXXXX.dat)
FILEB=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILEB-XXXXXXXXXX.dat)

ls -l ${FILEA} ${FILEB}

################################################################################

SNEAREND=0.0.0.0:${TUNNEL}
SFAREND=localhost:${FAREND}

stagecoach -C ${CERT}/stagecoach-servercert.pem -K ${CERT}/stagecoach-serverkey.pem -P ${CERT} -f ${SFAREND} -n ${SNEAREND} -s &
PIDSERVER=$!
sleep 2

ps -ef ${PIDSERVER}

CNEAREND=0.0.0.0:${NEAREND}
CFAREND=localhost:${TUNNEL}

stagecoach -C ${CERT}/stagecoach-clientcert.pem -K ${CERT}/stagecoach-clientkey.pem -P ${CERT} -f ${CFAREND} -n ${CNEAREND} -c &
PIDCLIENT=$!
sleep 2

ps -ef ${PIDCLIENT}

socat -u UDP4-RECV:? - > ${FILEA}

socat -u UDP4-RECV:? - > ${FILEB}

cat ${FILE1} | shaperbuffered -p 256 -s 256 -m 256 | socat -u - UDP4-DATAGRAM:?

cat ${FILE2} | shaperbuffered -p 256 -s 256 -m 256 | socat -u - UDP4-DATAGRAM:?

################################################################################

trap "kill -9 ${PIDCLIENT} ${PIDSERVER} 2> /dev/null; rm -f ${FILE1} ${FILE2} ${FILEA} ${FILEB}" HUP INT TERM

################################################################################

kill ${PIDCLIENT} ${PIDSERVER} 2> /dev/null

################################################################################

diff ${FILE1} ${FILEA} || XC=$((${XC} + 1))

diff ${FILE2} ${FILEB} || XC=$((${XC} + 1))

rm ${FILE1} ${FILE2} ${FILEA} ${FILEB}

################################################################################

exit ${XC}
