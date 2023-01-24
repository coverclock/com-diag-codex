/* vi: set ts=4 expandtab shiftwidth=4: */

/**
 * @file
 *
 * Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 */

#include "globals.h"

size_t bufsize = 65527; /* max(datagram)=(2^16-1)-8 */
const char * expected = (const char *)0;

const char * name = "invalid";
diminuto_ipv4_t ipv4address = 0;
diminuto_ipv6_t ipv6address = { 0, };
diminuto_port_t port = 0;
diminuto_ipv4_buffer_t ipv4string = { '\0', };
diminuto_ipv6_buffer_t ipv6string = { '\0', };
