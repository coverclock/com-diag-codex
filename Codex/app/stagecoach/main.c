/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2022-2023 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 * WORK IN PROGRESS
 *
 * This program provides an SSL tunnel between two UDP endpoints
 * while preserving datagram boundaries. It is agnostic as to the
 * data being passed via UDP, but it was written specifically to
 * provide this capability for the gpstool utility that is part of
 * the Hazer project (https://github.com/coverclock/com-diag-hazer).
 * gpstool can forward NMEA sentences, RTK messages, or CSV packets
 * to UDP port, but lacks any authentication or encryption capability.
 *
 * This program is based on the code in functionaltest-core-server
 * and functionaltest-core-client.
 *
 * I really really wanted NOT to have to write this program. I felt
 * that I should be able to script it using some combinaiton of maybe
 * socat and ssh. But I didn't see a way to preserve the record boundaries
 * of datagrams as the data propagates across the SSL tunnel. Some web
 * searches didn't change my mind, despite the claims of many commenters;
 * the solutions I saw worked most of the time by coincidence, in my
 * opinion.
 */

#include "com/diag/diminuto/diminuto_assert.h"
#include "com/diag/diminuto/diminuto_core.h"
#include "com/diag/diminuto/diminuto_delay.h"
#include "com/diag/diminuto/diminuto_fd.h"
#include "com/diag/diminuto/diminuto_hangup.h"
#include "com/diag/diminuto/diminuto_ipc4.h"
#include "com/diag/diminuto/diminuto_ipc6.h"
#include "com/diag/diminuto/diminuto_log.h"
#include "com/diag/diminuto/diminuto_mux.h"
#include "com/diag/diminuto/diminuto_terminator.h"
#include "com/diag/diminuto/diminuto_tree.h"
#include "com/diag/codex/codex.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

typedef enum Role { UNKNOWN = 0, PRODUCER = 1, CONSUMER = 2, } role_t;

static const char * program = "stagecoach";
static role_t role = UNKNOWN;
static const char * nearend = (const char *)0;
static const char * farend = (const char *)0;
static const char * expected = (const char *)0;
static size_t bufsize = 65527;
static const char * pathcaf = (const char *)0;
static const char * pathcap = (const char *)0;
static const char * pathcrl = (const char *)0;
static const char * pathcrt = (const char *)0;
static const char * pathkey = (const char *)0;
static const char * pathdhf = (const char *)0;
static int selfsigned = -1;

int main(int argc, char * argv[])
{
    char * endptr = (char *)0;
    int opt = '\0';
    extern char * optarg;

    (void)diminuto_core_enable();

    diminuto_log_setmask();

    program = ((program = strrchr(argv[0], '/')) == (char *)0) ? argv[0] : program + 1;

    while ((opt = getopt(argc, argv, "B:C:D:K:L:P:R:SVcf:e:psv?")) >= 0) {

        switch (opt) {

        case 'B':
        	bufsize = strtoul(optarg, &endptr, 0);
        	break;

        case 'C':
        	pathcrt = optarg;
        	break;

        case 'D':
        	pathdhf = optarg;
			break;

        case 'K':
        	pathkey = optarg;
        	break;

        case 'L':
        	pathcrl = (*optarg != '\0') ? optarg : (const char *)0;
        	break;

        case 'P':
        	pathcap = (*optarg != '\0') ? optarg : (const char *)0;
        	break;

        case 'R':
        	pathcaf = (*optarg != '\0') ? optarg : (const char *)0;
        	break;

        case 'S':
        	selfsigned = 0;
        	break;

        case 'c':
            role = CONSUMER;
            break;

        case 'e':
            expected = (*optarg != '\0') ? optarg : (const char *)0;
            break;

        case 'f':
        	farend = optarg;
        	break;

        case 'n':
        	nearend = optarg;
        	break;

        case 'p':
            role = PRODUCER;
            break;

        case 's':
        	selfsigned = 1;
        	break;

        case '?':
        	fprintf(stderr, "usage: %s [ -B BUFSIZE ] [ -C CERTIFICATEFILE ] [ -D DHPARMSFILE ] [ -K PRIVATEKEYFILE ] [ -L REVOCATIONFILE ] [ -P CERTIFICATESPATH ] [ -R ROOTFILE ] [ -e EXPECTED ] [ -f FAREND ] [ -n NEAREND ] [ -S | -s ] [ -p | -c ]\n", program);
            return 1;
            break;

        }

    }

	DIMINUTO_LOG_INFORMATION("%s: BEGIN B=%zu C=\"%s\" D=\"%s\" K=\"%s\" L=\"%s\" P=\"%s\" R=\"%s\" f=\"%s\" n=\"%s\" e=\"%s\" s=%d %s\n", program, bufsize, pathcrt, pathdhf, pathkey, (pathcrl == (const char *)0) ? "" : pathcrl, (pathcap == (const char *)0) ? "" : pathcap, (pathcaf == (const char *)0) ? "" : pathcaf, (farend == (const char *)0) ? "" : farend, (nearend == (const char *)0) ? "" : nearend, (expected == (const char *)0) ? "" : expected, selfsigned, (role == PRODUCER) ? "Producer" : (role == CONSUMER) ? "Consumer" : "Unknown");

    exit(0);
}
