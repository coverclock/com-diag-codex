/* vi: set ts=4 expandtab shiftwidth=4: */
#ifndef _H_STAGECOACH_PROTOCOLS_
#define _H_STAGECOACH_PROTOCOLS_

/**
 * @file
 *
 * Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 */

#include "types.h"

extern ssize_t datagram_receive(protocol_t type, int fd, void * bufferp, size_t size, address_t * addressp, port_t * portp);

extern ssize_t datagram_send(protocol_t type, int fd, void * bufferp, size_t size, const address_t * addressp, port_t port);

int rendezvous_service(protocol_t type, int port);

int rendezvous_ephemeral(protocol_t type);

extern int connection_nearend(protocol_t type, int sock, address_t * addressp, port_t * portp);

extern int connection_farend(protocol_t type, int sock, address_t * addressp, port_t * portp);

/*
 * NOT THREAD SAFE!
 */
extern const char * address2string(protocol_t type, const address_t * addressp, port_t port);

#endif
