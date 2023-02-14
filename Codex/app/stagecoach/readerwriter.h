/* vi: set ts=4 expandtab shiftwidth=4: */
#ifndef _H_STAGECOACH_READERWRITER_
#define _H_STAGECOACH_READERWRITER_

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

extern status_t readerwriter(role_t role, int fds, diminuto_mux_t * muxp, protocol_t udptype, int udpfd, address_t * receivedaddressp, port_t * receivedportp, const address_t * sendingaddressp, port_t sendingport, codex_connection_t * ssl, size_t bufsize, const char * expected);

#endif
