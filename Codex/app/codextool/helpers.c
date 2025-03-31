/* vi: set ts=4 expandtab shiftwidth=4: */

/**
 * @file
 *
 * Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 */

#include "helpers.h"
#include "com/diag/diminuto/diminuto_assert.h"
#include "com/diag/diminuto/diminuto_ipc4.h"
#include "com/diag/diminuto/diminuto_ipc6.h"
#include <stdio.h>

int connection_nearend(protocol_t type, int sock, address_t * addressp, port_t * portp)
{
    int rc = 0;

    switch (type) {
    case IPV4:
        rc = diminuto_ipc4_nearend(sock, &(addressp->address4), portp);
        break;
    case IPV6:
        rc = diminuto_ipc6_nearend(sock, &(addressp->address6), portp);
        break;
    default:
        diminuto_assert(false);
        break;
    }

    return rc;
}

int connection_farend(protocol_t type, int sock, address_t * addressp, port_t * portp)
{
    int rc = 0;

    switch (type) {
    case IPV4:
        rc = diminuto_ipc4_farend(sock, &(addressp->address4), portp);
        break;
    case IPV6:
        rc = diminuto_ipc6_farend(sock, &(addressp->address6), portp);
        break;
    default:
        diminuto_assert(false);
        break;
    }

    return rc;
}

/*
 * NOT THREAD SAFE!
 */
const char * address2string(protocol_t type, const address_t * addressp, port_t port)
{
    static diminuto_ipv4_buffer_t ipv4string = { '\0', }; /* uint8_t[4] => "255.255.255.255" */
    static diminuto_ipv6_buffer_t ipv6string = { '\0', }; /* uint16_t[8] => "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF" */
    static char buffer[sizeof(ipv6string) + sizeof("[]:65535")] = { '\0', };

    buffer[0] = '\0';

    switch (type) {
    case IPV4:
        (void)snprintf(buffer, sizeof(buffer), "%s:%d", diminuto_ipc4_address2string(addressp->address4, ipv4string, sizeof(ipv4string)), port);
        break;
    case IPV6:
        (void)snprintf(buffer, sizeof(buffer), "[%s]:%d", diminuto_ipc6_address2string(addressp->address6, ipv6string, sizeof(ipv6string)), port);
        break;
    default:
        diminuto_assert(false);
        break;
    }

    buffer[sizeof(buffer) - 1] = '\0';

    return buffer;
}
