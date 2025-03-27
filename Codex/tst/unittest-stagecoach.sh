#!/bin/bash
# Copyright 2025 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex
#
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
# the NMEA, RTK, PNT etc. data a lot less useful. So we avoid using TCP
# or TCP-like chanels when we can, and use them when we must.
#
# A stagecoach process in server mode acts as a proxy on the nearend for the
# farend server for the producer, and another as the proxy on the farend for
# the nearend client for the consumer.
#
# NOTES
#
# shaperbuffered and internettool are Diminuto bin utilities.
#
# REFERENCES
#
# Chip Overclock, "Better Never Than Late", 2017-02-16,
# <https://coverclock.blogspot.com/2017/02/better-never-than-late.html>

################################################################################
# PARAMETERS
################################################################################

ROOT=$(readlink -e $(dirname ${0}))

PROGRAM=$(basename ${0})

BLOCKSIZE=4096
BLOCKS=4096

TUNNEL=49123
NEAREND=49124
FAREND=49125

CERT="${ROOT}/../crt"

PEAKBYTERATE=256
SUSTAINEDBYTERATE=256
MAXIMUMBURSTSIZE=256

XC=0

# This password is only used for testing.
export COM_DIAG_CODEX_SERVER_PASSWORD=st8g3c08ch

echo "${PROGRAM}: BEGIN" 1>&2

################################################################################
# FILES
################################################################################

FILEPRODUCERSOURCE=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILEPRODUCERSOURCE-XXXXXXXXXX.dat)
FILECONSUMERSOURCE=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILECONSUMERSOURCE-XXXXXXXXXX.dat)
FILEPRODUCERSINK=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILEPRODUCERSINK-XXXXXXXXXX.dat)
FILECONSUMERSINK=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILECONSUMERSINK-XXXXXXXXXX.dat)

dd if=/dev/urandom bs=${BLOCKSIZE} count=${BLOCKS} iflag=fullblock of=${FILEPRODUCERSOURCE}

dd if=/dev/urandom bs=${BLOCKSIZE} count=${BLOCKS} iflag=fullblock of=${FILECONSUMERSOURCE}

FILES="${FILEPRODUCERSOURCE} ${FILEPRODUCERSINK} ${FILECONSUMERSOURCE} ${FILECONSUMERSINK}"

ls -l ${FILES}

################################################################################
# PROCESSES
################################################################################

# Near End                             Far End
# __________________________           __________________________
#                     proxy            proxy
#                     consumer         producer
# PRODUCER <---UDP--> CLIENT <==SSL==> SERVER <---UDP--> CONSUMER
#  |                   |                |                 |
# gpstool             stagecoach       stagecoach        rtktool
# rover               -c               -s                router

stagecoach -C ${CERT}/stagecoach-servercert.pem -K ${CERT}/stagecoach-serverkey.pem -P ${CERT} -f localhost:${FAREND} -n 0.0.0.0:${TUNNEL} -s &
PIDSERVER=$!
sleep 5

stagecoach -C ${CERT}/stagecoach-clientcert.pem -K ${CERT}/stagecoach-clientkey.pem -P ${CERT} -f localhost:${TUNNEL} -n 0.0.0.0:${NEAREND} -c &
PIDCLIENT=$!
sleep 5

cat ${FILEPRODUCERSOURCE} | shaperbuffered -p ${PEAKBYTERATE} -s ${SUSTAINEDBYTERATE} -m ${MAXIMUMBURSTSIZE} | internettool -4 -u -E localhost:${NEAREND} > ${FILEPRODUCERSINK} &
PIDPRODUCER=$!

cat ${FILECONSUMERSOURCE} | shaperbuffered -p ${PEAKBYTERATE} -s ${SUSTAINEDBYTERATE} -m ${MAXIMUMBURSTSIZE} | internettool -4 -u -E ${FAREND} > ${FILECONSUMERSINK} &
PIDCONSUMER=$!

PIDS="${PIDCLIENT} ${PIDSERVER} ${PIDCONSUMER} ${PIDPRODUCER}"

ps -ef ${PIDS}

################################################################################
# EXECUTE
################################################################################

trap "kill -9 ${PIDS} 2> /dev/null; rm -f ${FILES}" HUP INT TERM

wait ${PIDPRODUCER}

sleep 5

kill ${PIDS} 2> /dev/null

################################################################################
# RESULTS
################################################################################

diff ${FILEPRODUCERSOURCE} ${FILEPRODUCERSINK} || XC=$((${XC} + 1))

diff ${FILECONSUMERSOURCE} ${FILECONSUMERSINK} || XC=$((${XC} + 1))

rm ${FILEPRODUCERSOURCE} ${FILECONSUMERSOURCE} ${FILEPRODUCERSINK} ${FILECONSUMERSINK}

################################################################################
# DONE
################################################################################

echo "${PROGRAM}: END ${XC}" 1>&2

exit ${XC}
