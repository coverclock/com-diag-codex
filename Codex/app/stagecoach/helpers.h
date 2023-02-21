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
 * This declares the API for the helper functions.
 */

#include "types.h"

/**
 * Receive a datagram via IPV4 or IPv6.
 * @param type is the protocol type.
 * @param fd is the file descriptor of the UDP socket.
 * @param bufferp points to the buffer.
 * @param size is the size of the buffer in bytes.
 * @param addressp points to where the received address is stored.
 * @param portp points to where the received port is stored.
 * @return the size of the datagram in bytes, 0 for close, <0 for error.
 */
extern ssize_t datagram_receive(protocol_t type, int fd, void * bufferp, size_t size, address_t * addressp, port_t * portp);

/**
 * Send a datagram via IPV4 or IPv6.
 * @param type is the protocol type.
 * @param fd is the file descriptor of the UDP socket.
 * @param bufferp points to the buffer.
 * @param size is the size of the buffer in bytes.
 * @param addressp points the send address.
 * @param portp points to the send port.
 * @return the size of the datagram in bytes, 0 for close, <0 for error.
 */
extern ssize_t datagram_send(protocol_t type, int fd, void * bufferp, size_t size, const address_t * addressp, port_t port);

/**
 * Creates a UDP socket bound to the specified port number.
 * @param type is the protocol type.
 * @param port is the port number.
 * @return the UDP socket or <0 for error.
 */
extern int rendezvous_service(protocol_t type, port_t port);

/**
 * Creates a UDP socket bound to an ephemeral port.
 * @param type is the protocol type.
 * @return the UDP socket or <0 for error.
 */
extern int rendezvous_ephemeral(protocol_t type);

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
