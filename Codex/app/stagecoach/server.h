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
#include "com/diag/diminuto/diminuto_mux.h"
#include "types.h"

extern int server(diminuto_mux_t * muxp, protocol_t biotype, int biofd, protocol_t udptype, int udpfd, codex_context_t * ctx, codex_connection_t * ssl);

#endif
