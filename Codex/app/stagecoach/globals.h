/* vi: set ts=4 expandtab shiftwidth=4: */
#ifndef _H_GLOBALS_
#define _H_GLOBALS_

/**
 * @file
 *
 * Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 */

#include "types.h"

extern size_t bufsize;
extern const char * expected;

extern const char * name;
extern diminuto_ipv4_t ipv4address;
extern diminuto_ipv6_t ipv6address;
extern diminuto_port_t port;
extern diminuto_ipv4_buffer_t ipv4string;
extern diminuto_ipv6_buffer_t ipv6string;

#endif
