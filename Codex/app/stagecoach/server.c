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

status_t server(bool introduce, int fds, diminuto_mux_t * muxp, protocol_t udptype, int udpfd, const address_t * serviceaddressp, port_t serviceport, codex_connection_t * ssl, size_t bufsize, const char * expected, sticks_t keepalive)
{
    address_t lastaddress = { 0, };
    diminuto_port_t lastport = 0;

    return readerwriter(SERVER, introduce, fds, muxp, udptype, udpfd, &lastaddress, &lastport, serviceaddressp, serviceport, ssl, bufsize, expected, keepalive);
}
