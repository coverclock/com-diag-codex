/* vi: set ts=4 expandtab shiftwidth=4: */

/**
 * @file
 *
 * Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 */

#include "com/diag/codex/codex.h"
#include "globals.h"
#include "helpers.h"
#include "readerwriter.h"
#include "server.h"
#include "types.h"

status_t client(int fds, diminuto_mux_t * muxp, protocol_t udptype, int udpfd, codex_connection_t * ssl, size_t bufsize, const char * expected, sticks_t keepalive)
{
    static address_t lastaddress = { 0, };
    static diminuto_port_t lastport = 0;

    return readerwriter(CLIENT, fds, muxp, udptype, udpfd, &lastaddress, &lastport, &lastaddress, lastport, ssl, bufsize, expected, keepalive);
}
