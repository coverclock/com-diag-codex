/* vi: set ts=4 expandtab shiftwidth=4: */
#ifndef _H_PROCESS_
#define _H_PROCESS_

/**
 * @file
 *
 * Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 */

#include "com/diag/codex/codex.h"
#include "types.h"

extern int client_proxy(int muxfd, protocol_t udptype, int udpfd, codex_connection_t * ssl);

extern int server_proxy(int muxfd, protocol_t udptype, int udpfd, codex_connection_t * ssl);

#endif
