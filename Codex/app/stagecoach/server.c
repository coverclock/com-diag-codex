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
#include "protocols.h"
#include "readerwriter.h"
#include "server.h"
#include "types.h"

static address_t address = { 0, };
static diminuto_port_t port = 0;

status_t server(int fds, diminuto_mux_t * muxp, protocol_t udptype, int udpfd, const address_t * serviceaddressp, port_t serviceport, codex_connection_t * ssl, size_t bufsize, const char * expected)
{
    return readerwriter(SERVER, fds, muxp, udptype, udpfd, &address, &port, serviceaddressp, serviceport, ssl, bufsize, expected);
}
