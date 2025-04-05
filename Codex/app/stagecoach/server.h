/* vi: set ts=4 expandtab shiftwidth=4: */
#ifndef _H_STAGECOACH_SERVER_
#define _H_STAGECOACH_SERVER_

/**
 * @file
 *
 * Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 *
 * This describes the API for the Stagecoach server. The server acts
 * as a proxy for the actual client, receiving a data stream from the SSL
 * tunnel, reconstructs the original UDP datagram, and sends it to the
 * service host and port. Datagrams received from the service host and port
 * is written back through the SSL tunnel.
 */

#include "com/diag/codex/codex.h"
#include "com/diag/diminuto/diminuto_mux.h"
#include "types.h"

/**
 * Implement the server-side client proxy for Stagecoach.
 * @param introduce indicates send an initial keepalive.
 * @param fds is the number of ready fds from the multiplexer.
 * @param muxp points to the multiplexer object.
 * @param udptype is the type of the UDP socket, IPV4 or IPV6.
 * @param udpfd is the file descriptor for the UDP socket.
 * @param serviceaddressp points to the service address object.
 * @param serviceport is the service port number.
 * @param ssl points to the SSL object.
 * @param bufsize is the maximum buffer size to be allocated by the client.
 * @param expected is the expected server FQDN or null if no verification.
 * @param keepalive is the duration of the keepalive in ticks, -1 for none.
 * @return the status.
 */
extern status_t server(bool introduce, int fds, diminuto_mux_t * muxp, protocol_t udptype, int udpfd, const address_t * serviceaddressp, port_t serviceport, codex_connection_t * ssl, size_t bufsize, const char * expected, sticks_t keepalive);

#endif
