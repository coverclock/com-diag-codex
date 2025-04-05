/* vi: set ts=4 expandtab shiftwidth=4: */
#ifndef _H_CODEXTOOL_READERWRITER_
#define _H_CODEXTOOL_READERWRITER_

/**
 * @file
 *
 * Copyright 2023-2025 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 *
 * This describes the API for the common reader-writer implementation used
 * by both the client and server functions.
 */

#include "com/diag/codex/codex.h"
#include "com/diag/diminuto/diminuto_mux.h"
#include "types.h"

/**
 * This implements the reader and writer state machines that are called after
 * every new call to the multiplexor, which uses the select(2) system call.
 * @param role is the role of the calling function, CLIENT or SERVER.
 * @param introduce indicates send an initial keepalive.
 * @param fds is the number of file descriptors that are ready, or <0 for error.
 * @param muxp is the multiplexor object.
 * @param infd is the input file descriptor (nominally STDIN_FILENO).
 * @param ssl points to the SSL object.
 * param outfd is the output file descriptor (nominally STDOUT_FILENO).
 * @param bufsize is the buffer size to be allocated in bytes.
 * @param expected points to the expected FQDN or null for no verification.
 * @param keepalive is the keepalive duration in ticks.
 * @return the status.
 */
extern status_t readerwriter(role_t role, bool introduce, int fds, diminuto_mux_t * muxp, int infd, codex_connection_t * ssl, int outfd, size_t bufsize, const char * expected, sticks_t keepalive);

#endif
