#!/bin/bash -x
# Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
# Licensed under the terms in LICENSE.txt
# Chip Overclock (mailto:coverclock@diag.com)
# https://github.com/coverclock/com-diag-codex

# Note that the use of the IPv4 "unspecified" address for the near end
# end point serves two purposes: it forces Diminuto to choose IPV4 instead
# of the default of IPv6, and serves as a wild card for the socket binding
# address. Using "localhost" etc. for this purpose will prevent remote UDP
# sources from connecting.

# rtk2dgm -- [tumbleweed] -- stagecoach -c
#                                |
#                          [stagecoachssl]
#                                |
# rtktool -- [tumbleweed] -- stagecoach -s

# rtk2dgm and rtktool are programs from the Hazer project repository that
# handle RTCM messages. rtk2dgm simulates a Hazer Tumbleweed differential
# GNSS rover. rtktool is an Hazer Tumbleweed router that handles sending
# RTCM updates from a single Hazer Tumbleweed differential GNSS base to
# multiple rovers.
 
# GNSS: Global Navigation Satellite Systems.
# Hazer: a repository of GNSS tools.
# HTTPS: HyperText Transfer Protocol Secure (HTTP over SSL).
# IP: Internet Protocol.
# RTCM: Radio Technical Commission for Maritime Services.
# RTK: Real-Time Kinematics.
# Stagecoach: a sub-project of Codex that forwards UDP datagrams over SSL.
# SSH: Secure SHell.
# SSL: Secure Socket Layer (also used by HTTPS, SSH, etc.).
# Tumbleweed: a sub-project of Hazer that supports differential GNSS.
# UDP: User Datagram Protocol, a protocol on top of IP.

STAGECOACH_CLIENT_NEAREND=0.0.0.0:tumbleweed
STAGECOACH_CLIENT_FAREND=localhost:stagecoach
STAGECOACH_SERVER_NEAREND=0.0.0.0:stagecoach
STAGECOACH_SERVER_FAREND=eljefe:tumbleweed
