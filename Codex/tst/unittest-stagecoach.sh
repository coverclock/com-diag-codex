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
# Why not just use SSL to begin with? Because stream-based communication
# channels like TCP (which is what SSL uses), or even third-party protocols
# like Google's QUIC (which basically implements all of TCP's mechanisms in
# user space on top of UDP), mess up the real-time nature of the UDP datagrams
# and make the NMEA, RTK, PNT etc. data a lot less accurate. So we avoid using
# TCP or TCP-like chanels when we can, and use them when we must (like when
# secrecy and strong authentication is really necessary).
#
# A stagecoach process in server mode acts as a proxy on the nearend for the
# farend server for the producer, and another as the proxy on the farend for
# the nearend client for the consumer.
#
# NOTES
#
# shaper, phex, and internettool are Diminuto bin utilities.
#
# REFERENCES
#
# Chip Overclock, "Better Never Than Late", 2017-02-16,
# <https://coverclock.blogspot.com/2017/02/better-never-than-late.html>

################################################################################
# BEGIN
################################################################################

PROGRAM=$(basename ${0})

echo "${PROGRAM}: BEGIN" 1>&2

XC=0

BLOCKSIZE=4096
BLOCKS=16

TUNNEL=49123
NEAREND=49124
FAREND=49125

ROOT=$(readlink -e $(dirname ${0}))
CERT="${ROOT}/../crt"

BUFFERSIZE=256
PEAKBYTERATE=256
SUSTAINEDBYTERATE=256
MAXIMUMBURSTSIZE=256

# This password is only used for testing.
export COM_DIAG_CODEX_SERVER_PASSWORD=st8g3c08ch

################################################################################
# FILES
################################################################################

echo "${PROGRAM}: FILES" 1>&2

FILESOURCE=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILESOURCE-XXXXXXXXXX.dat)
FILESINK=$(mktemp ${TMPDIR:-"/tmp"}/$(basename ${0} .sh)-FILESINK-XXXXXXXXXX.dat)

dd if=/dev/urandom bs=${BLOCKSIZE} count=${BLOCKS} iflag=fullblock of=${FILESOURCE}

FILES="${FILESOURCE} ${FILESINK}"

ls -l ${FILES}

################################################################################
# PROCESSES
################################################################################

echo "${PROGRAM}: PROCESSES" 1>&2

# Near End                             Far End
# __________________________           __________________________
#                     proxy            proxy
#                     consumer         producer
# PRODUCER <---UDP--> CLIENT <==SSL==> SERVER <---UDP--> CONSUMER
#  |                   |                |                 |
# gpstool             stagecoach       stagecoach        rtktool
# rover               -c               -s                router

stagecoach -b ${BUFFERSIZE} -C ${CERT}/stagecoach-servercert.pem -K ${CERT}/stagecoach-serverkey.pem -P ${CERT} -f localhost:${FAREND} -n 0.0.0.0:${TUNNEL} -s &
PIDSERVER=$!
sleep 5

stagecoach -b ${BUFFERSIZE} -C ${CERT}/stagecoach-clientcert.pem -K ${CERT}/stagecoach-clientkey.pem -P ${CERT} -f localhost:${TUNNEL} -n 0.0.0.0:${NEAREND} -c &
PIDCLIENT=$!
sleep 5

# Loopback
internettool -b ${BUFFERSIZE} -4 -u -e :${FAREND} &
PIDCONSUMER=$!
sleep 5

cat ${FILESOURCE} | shaper -d -v -b ${BUFFERSIZE} -p ${PEAKBYTERATE} -s ${SUSTAINEDBYTERATE} -m ${MAXIMUMBURSTSIZE} | phex -x | internettool -b ${BUFFERSIZE} -4 -u -E localhost:${NEAREND} > ${FILESINK} &
PIDPRODUCER=$!

PIDS="${PIDCLIENT} ${PIDSERVER} ${PIDCONSUMER} ${PIDPRODUCER}"

ps -f ${PIDS}

################################################################################
# EXECUTE
################################################################################

echo "${PROGRAM}: EXECUTE" 1>&2

trap "ps -f ${PIDS}; kill -9 ${PIDS} 2> /dev/null; ls -l ${FILES}; rm -f ${FILES} 2> /dev/null" HUP INT TERM

wait ${PIDPRODUCER}

sleep 5

ps -f ${PIDS}

kill ${PIDS} 2> /dev/null

################################################################################
# RESULTS
################################################################################

echo "${PROGRAM}: RESULTS" 1>&2

ls -l ${FILES}

diff ${FILESOURCE} ${FILESINK} || XC=$((${XC} + 1))

rm -f ${FILESOURCE} ${FILESINK}

################################################################################
# END
################################################################################

echo "${PROGRAM}: END ${XC}" 1>&2

exit ${XC}
