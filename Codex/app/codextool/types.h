/* vi: set ts=4 expandtab shiftwidth=4: */
#ifndef _H_CODEXTOOL_TYPES_
#define _H_CODEXTOOL_TYPES_

/**
 * @file
 *
 * Copyright 2023-2025 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 *
 * This defines the types used by this application.
 */

#include "com/diag/diminuto/diminuto_types.h"

/**
 * Enumerate the roles.
 * The nomenclature is a little confusing here. The SERVER role runs
 * on the server side of the connection, but acts as a client proxy
 * to the actual server. Similarly, the CLIENT role runs on the client
 * side of the connection, but acts as a server proxy for the actual
 * client. The role specifies on which side of the SSL connection the
 * codextool program is running, not how it relates to the application.
 */
typedef enum Role { INVALID = '?', CLIENT = 'c', SERVER = 's', } role_t;

/**
 * Enumerate the protocols used for the SSL tunnel.
 */
typedef enum Protocol { OTHER = '?', IPV4 = '4', IPV6 = '6', } protocol_t;

/**
 * Enumerate the status that may be returned by the client and the server,
 * indicating whether the process should continue, shutdown and restart the
 * SSL tunnel, or close and exit.
 */
typedef enum Status { UNKNOWN = '?', SSLDONE = 'S', STDDONE = 's', CONTINUE = '-', } status_t;

/**
 * Enumerate the direction of the state machine: reading or writing.
 * Once again, the nomenclature can be a little confusing. In this
 * context, the READER is the SSL reading state machine, and the
 * WRITER is the SSL writing state machine. The READER sends to the
 * UDP port, and the WRITER receives from the UDP port.
 */
typedef enum Direction { READER = 0, WRITER = 1, DIRECTIONS = 2, } direction_t;

/**
 * This describes the format of an address object, which can encapsulate
 * either an IPv6 or an IPv4 address.
 */
typedef union Address {
    diminuto_ipv6_t address6;
    diminuto_ipv4_t address4;
    uint16_t word[sizeof(diminuto_ipv6_t) / sizeof(uint16_t)];
    uint8_t byte[sizeof(diminuto_ipv6_t) / sizeof(uint8_t)];
} address_t;

/**
 * This describes the type of a port number variable.
 */
typedef diminuto_port_t port_t;

/**
 * This decribes the type of an unsigned value of ticks.
 */
typedef diminuto_ticks_t ticks_t;

/**
 * This decribes the type of a signed value of ticks.
 */
typedef diminuto_sticks_t sticks_t;

#endif
