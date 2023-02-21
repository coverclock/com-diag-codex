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
 *
 * This declares the common reader-writer implementation used by the
 * client and server functions.
 */

#include "com/diag/codex/codex.h"
#include "com/diag/diminuto/diminuto_mux.h"
#include "types.h"

/**
 * This implements the reader and writer state machines that are called after
 * every new call to the multiplexor, which uses the select(2) system call.
 * @param role is the role of the calling function, CLIENT or SERVER.
 * @param fds is the number of file descriptors that are ready, or <0 for error.
 * @param muxp is the multiplexor object.
 * @param udptype is the protocol type of the UDP socket, IPv4 or IPv6.
 * @param receivedaddressp points to the address of the received datagram.
 * @param receivedportp points to the port of the received datagram.
 * @param sendingaddressp points to the address to where datagrams are sent.
 * @param sendingport is the port to where datagrams are sent.
 * @param ssl points to the SSL object.
 * @param bufsize is the buffer size to be allocated in bytes.
 * @param expected points to the expected FQDN or null for no verification.
 * @param keepalive is the keepalive duration in ticks.
 * @return the status.
 */
extern status_t readerwriter(role_t role, int fds, diminuto_mux_t * muxp, protocol_t udptype, int udpfd, address_t * receivedaddressp, port_t * receivedportp, const address_t * sendingaddressp, port_t sendingport, codex_connection_t * ssl, size_t bufsize, const char * expected, sticks_t keepalive);

#endif
