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

# In normal (production) circumstances, the CLIENT and SERVER ports would
# be the same, and the client and server Stagecoach instances would be
# running on different computers.

STAGECOACHFAREND=localhost
STAGECOACHNEAREND=0.0.0.0
STAGECOACHCLIENT=24040
STAGECOACHSSL=25050
STAGECOACHSERVER=26060
