#!/bin/bash
# Copyright 2025 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

# stagcoach is a tool built on top of the Codex and Diminuto libraries,
# which is used support of gpstool that is built on top of the Hazer and
# Diminuto libraries. gpstool can transmit a variety of information -
# NMEA sentences, RTK updates, or CSV PNT information, via UDP datagrams to
# a remote system, which may also be running gpstool or another utility
# like rtktool. This facility is used, for example, with Differential GNSS
# systems, remote tracking applications, etc. stagecoach is a go-between
# tool that receives UDP datagrams, tunnels them through an SSL tunnel, then
# forwards them via UDP to the receiver.
#
# Why not just use SSL to begin with? Because communication channels that
# use TCP, like SSL, or even those that use third-party mechanisms like
# Google's QUIC (which basically implements all of TCP's mechanisms in
# user space), mess up the real-time nature of the UDP datagrams and make
# the NMEA, RTK, PNT etc. data a lot less useful.
#
# A stagecoach process in server mode acts as a proxy on the nearend for the
# farend server for the producer, and another as the proxy on the farend for
# the nearend client for the consumer. Confusingly, the proxy server stagecoach
# runs in client (-c) mode, while the proxy client stagecoach runs in server
# (-s) mode.
#
#                     proxy            proxy
# PRODUCER <---UDP--> SERVER <==SSL==> CLIENT <---UDP--> CONSUMER
# nearend             nearend          farend            farend
#  |                   |                |                 |
# gpstool             stagecoach -c    stagecoach -s     rtktool
# rover                                                  router

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

SNEAREND=0.0.0.0:${TUNNEL}
SFAREND=localhost:${FAREND}

CNEAREND=0.0.0.0:${NEAREND}
CFAREND=localhost:${TUNNEL}

################################################################################

FILEPRODUCERSOURCE=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILEPRODUCERSOURCE-XXXXXXXXXX.dat)
FILECONSUMERSOURCE=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILECONSUMERSOURCE-XXXXXXXXXX.dat)

dd if=/dev/urandom bs=${BLOCKSIZE} count=${BLOCKS} iflag=fullblock of=${FILEPRODUCERSOURCE}
dd if=/dev/urandom bs=${BLOCKSIZE} count=${BLOCKS} iflag=fullblock of=${FILECONSUMERSOURCE}

FILEPRODUCERSINK=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILEPRODUCERSINK-XXXXXXXXXX.dat)
FILECONSUMERSINK=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILECONSUMERSINK-XXXXXXXXXX.dat)

FILES="${FILEPRODUCERSOURCE} ${FILECONSUMERSOURCE} ${FILEPRODUCERSINK} ${FILECONSUMERSINK}"

ls -l ${FILES}

################################################################################

stagecoach -C ${CERT}/stagecoach-servercert.pem -K ${CERT}/stagecoach-serverkey.pem -P ${CERT} -f ${SFAREND} -n ${SNEAREND} -s &
PIDSERVER=$!
sleep 5

stagecoach -C ${CERT}/stagecoach-clientcert.pem -K ${CERT}/stagecoach-clientkey.pem -P ${CERT} -f ${CFAREND} -n ${CNEAREND} -c &
PIDCLIENT=$!
sleep 5

socat -u UDP4-RECV:? - > ${FILEPRODUCERSINK} &
PIDPRODUCERSINK=$!

socat -u UDP4-RECV:? - > ${FILECONSUMERSINK} &
PIDCONSUMERSINK=$!

cat ${FILEPRODUCERSOURCE} | shaperbuffered -p 256 -s 256 -m 256 | socat -u - UDP4-DATAGRAM:? &
PIDPRODUCERSOURCE=$!

cat ${FILECONSUMERSOURCE} | shaperbuffered -p 256 -s 256 -m 256 | socat -u - UDP4-DATAGRAM:? &
PIDCONSUMERSOURCE=$!

PIDS="${PIDCLIENT} ${PIDSERVER} ${PIDPRODUCERSINK} ${PIDCONSUMERSINK} ${PIDPRODUCERSOURCE} ${PIDPRODUCERSINK}"

ps -ef ${PIDS}

trap "kill -9 ${PIDS} 2> /dev/null; rm -f ${FILES}" HUP INT TERM

################################################################################

wait ${PIDPRODUCERSORUCE}

wait ${PIDCONSUMERSOURCE}

sleep 5

kill ${PIDS} 2> /dev/null

################################################################################

diff ${FILEPRODUCERSOURCE} ${FILEPRODUCERSINK} || XC=$((${XC} + 1))

diff ${FILECONSUMERSOURCE} ${FILECONSUMERSINK} || XC=$((${XC} + 1))

rm ${FILEPRODUCERSOURCE} ${FILECONSUMERSOURCE} ${FILEPRODUCERSINK} ${FILECONSUMERSINK}

################################################################################

exit ${XC}
