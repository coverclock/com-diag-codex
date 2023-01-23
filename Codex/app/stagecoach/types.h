/* vi: set ts=4 expandtab shiftwidth=4: */
#ifndef _H_TYPES_
#define _H_TYPES_

/**
 * @file
 *
 * Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 */

#include <stdbool.h>
#include <stdint.h>
#include "com/diag/diminuto/diminuto_types.h"

typedef enum Role { INVALID = '?', CLIENT = 'c', SERVER = 's', } role_t;

typedef enum Protocol { UNKNOWN = '?', IPV4 = '4', IPV6 = '6', } protocol_t;

typedef uint16_t prefix_t;

#endif
