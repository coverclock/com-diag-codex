/* vi: set ts=4 expandtab shiftwidth=4: */
#ifndef _H_STAGECOACH_CLIENT_
#define _H_STAGECOACH_CLIENT_

/**
 * @file
 *
 * Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 *
 * This describes the API for the Stagecoach client. The client acts
 * as a proxy for the actual server, receiving UDP datagrams from the
 * actual client and forwarding them through the SSL tunnel. Data read
 * from the SSL tunnel is reconstructed back into datagrams and sent to
 * the sender of the most recent datagram.
 */

#include "com/diag/codex/codex.h"
#include "com/diag/diminuto/diminuto_mux.h"
#include "types.h"

/**
 * Implement the client-side server proxy for Stagecoach.
 * @param fds is the number of ready fds from the multiplexer.
 * @param muxp points to the multiplexer object.
 * @param udptype is the type of the UDP socket, IPV4 or IPV6.
 * @param udpfd is the file descriptor for the UDP socket.
 * @param ssl points to the SSL object.
 * @param bufsize is the maximum buffer size to be allocated by the client.
 * @param expected is the expected server FQDN or null if no verification.
 * @param keepalive is the duration of the keepalive in ticks, -1 for none.
 * @return the status.
 */
extern status_t client(int fds, diminuto_mux_t * muxp, protocol_t udptype, int udpfd, codex_connection_t * ssl, size_t bufsize, const char * expected, sticks_t keepalive);

#endif
