/* vi: set ts=4 expandtab shiftwidth=4: */
#ifndef _H_STAGECOACH_TYPES_
#define _H_STAGECOACH_TYPES_

/**
 * @file
 *
 * Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 */

#include "com/diag/diminuto/diminuto_types.h"

/**
 * The nomenclature is a little confusing here. The SERVER role runs
 * on the server side of the connection, but acts as a client proxy
 * to the actual server. Similarly, the CLIENT role runs on the client
 * side of the connection, but acts as a server proxy for the actual
 * client. The role specifies on which side of the SSL connection the
 * Stagecoach program is running, not how it relates to the application.
 */
typedef enum Role { INVALID = '?', CLIENT = 'c', SERVER = 's', } role_t;

typedef enum Protocol { OTHER = '?', IPV4 = '4', IPV6 = '6', } protocol_t;

typedef enum Status { UNKNOWN = '?', SSLDONE = 'S', UDPDONE = 'U', CONTINUE = '-', } status_t;

/**
 * Once again, the nomenclature can be a little confusing. In this
 * context, the READER is the SSL reading state machine, and the
 * WRITER is the SSL writing state machine. The READER sends to the
 * UDP port, and the WRITER receives from the UDP port.
 */
typedef enum Direction { READER = 0, WRITER = 1, DIRECTIONS = 2, } direction_t;

typedef union Address {
    diminuto_ipv6_t address6;
    diminuto_ipv4_t address4;
    uint16_t word[sizeof(diminuto_ipv6_t) / sizeof(uint16_t)];
    uint8_t byte[sizeof(diminuto_ipv6_t) / sizeof(uint8_t)];
} address_t;

typedef diminuto_port_t port_t;

#endif
