/* vi: set ts=4 expandtab shiftwidth=4: */

/**
 * @file
 *
 * Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 */

#include "com/diag/diminuto/diminuto_assert.h"
#include "com/diag/diminuto/diminuto_core.h"
#include "com/diag/diminuto/diminuto_ipc4.h"
#include "com/diag/diminuto/diminuto_ipc6.h"
#include "com/diag/diminuto/diminuto_log.h"
#include "globals.h"
#include "proxy.h"

static diminuto_port_t last = 0;

int client_proxy(int muxfd, protocol_t udptype, int udpfd, codex_connection_t * ssl)
{
    int rc = 0;
    ssize_t length = 0;
    diminuto_ipc_endpoint_t farendpoint = { 0 };
    codex_state_t state = CODEX_STATE_IDLE;
    codex_header_t header = 0;
    uint8_t * here = (uint8_t *)0;
    codex_serror_t serror = CODEX_SERROR_NONE;
    int mask = 0;

    return -1;
}

int server_proxy(int muxfd, protocol_t udptype, int udpfd, codex_connection_t * ssl)
{
    int rc = 0;
    ssize_t length = 0;
    diminuto_ipc_endpoint_t farendpoint = { 0 };
    codex_state_t state = CODEX_STATE_IDLE;
    codex_header_t header = 0;
    uint8_t * here = (uint8_t *)0;
    codex_serror_t serror = CODEX_SERROR_NONE;
    int mask = 0;

    return -1;
}
