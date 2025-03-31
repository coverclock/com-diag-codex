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
 *
 * This describes the API for the helper functions.
 */

#include "types.h"

/**
 * Extract the near end address and port for the specified socket.
 * @param type is the prototol type.
 * @param sock is the file descriptor of the socket.
 * @param addressp points to where the near end address is stored.
 * @param portp points to where the near end port is stored.
 * @return >=0 for success, <0 for error.
 */
extern int connection_nearend(protocol_t type, int sock, address_t * addressp, port_t * portp);

/**
 * Extract the far end address and port for the specified socket.
 * @param type is the prototol type.
 * @param sock is the file descriptor of the socket.
 * @param addressp points to where the far end address is stored.
 * @param portp points to where the far end port is stored.
 * @return >=0 for success, <0 for error.
 */
extern int connection_farend(protocol_t type, int sock, address_t * addressp, port_t * portp);

/**
 * Convert and address object and a port number into a printable string.
 * NOT THREAD SAFE!
 * @param type is the protocol type.
 * @param addressp points to the address.
 * @param port is the port number.
 * @return a pointer to the printable string.
 */
extern const char * address2string(protocol_t type, const address_t * addressp, port_t port);

#endif
