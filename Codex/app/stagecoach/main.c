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
#include "../src/codex.h"

typedef enum Role { UNKNOWN = 0, CLIENT = 1, SERVER = 2, } role_t;

typedef uint16_t length_t;

static const char * program = "stagecoach";
static role_t role = UNKNOWN;
static const char * nearend = (const char *)0;
static const char * farend = (const char *)0;
static const char * expected = (const char *)0;
static size_t bufsize = 65527; /* (2^16-1)-8 */
static const char * pathcaf = (const char *)0;
static const char * pathcap = (const char *)0;
static const char * pathcrl = (const char *)0;
static const char * pathcrt = (const char *)0;
static const char * pathkey = (const char *)0;
static const char * pathdhf = (const char *)0;
static bool selfsigned = true;
static bool verbose = false;

int main(int argc, char * argv[])
{
    int opt = '\0';
    char * endptr = (char *)0;
    int rc = -1;
    length_t length = 0;
    uint8_t * buffer = (uint8_t *)0;
    diminuto_mux_t mux = { 0 };
    diminuto_ipc_endpoint_t farendpoint = { 0 };
    diminuto_ipc_endpoint_t nearendpoint = { 0 };
    codex_context_t * ctx = (codex_context_t *)0;
    extern char * optarg;

    (void)diminuto_core_enable();

    diminuto_log_setmask();

    program = ((program = strrchr(argv[0], '/')) == (char *)0) ? argv[0] : program + 1;

    while ((opt = getopt(argc, argv, "B:C:D:K:L:MP:R:ce:f:mn:sv?")) >= 0) {

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

        case 'M':
        	selfsigned = true;
        	break;

        case 'P':
        	pathcap = (*optarg != '\0') ? optarg : (const char *)0;
        	break;

        case 'R':
        	pathcaf = (*optarg != '\0') ? optarg : (const char *)0;
        	break;

        case 'c':
            role = CLIENT;
            break;

        case 'e':
            expected = (*optarg != '\0') ? optarg : (const char *)0;
            break;

        case 'f':
        	farend = optarg;
        	break;

        case 'm':
        	selfsigned = false;
        	break;

        case 'n':
        	nearend = optarg;
        	break;

        case 's':
            role = SERVER;
            break;

        case 'v':
            verbose = true;
            break;

        case '?':
        	fprintf(stderr, "usage: %s [ -v ] [ -B BUFSIZE ] [ -C CERTIFICATEFILE ] [ -D DHPARMSFILE ] [ -K PRIVATEKEYFILE ] [ -L REVOCATIONFILE ] [ -P CERTIFICATESPATH ] [ -R ROOTFILE ] [ -e EXPECTEDDOMAIN ] [ -f FAREND ] [ -n NEAREND ] [ -M | -m ] [ -c | -s ]\n", program);
            return 1;
            break;

        }

    }

	DIMINUTO_LOG_INFORMATION("%s: BEGIN v=%d B=%zu C=\"%s\" D=\"%s\" K=\"%s\" L=\"%s\" M=%d P=\"%s\" R=\"%s\" e=\"%s\" f=\"%s\" n=\"%s\" %s\n",
        program,
        verbose,
        bufsize,
        (pathcrt == (const char *)0) ? "" : pathcrt,
        (pathdhf == (const char *)0) ? "" : pathdhf,
        (pathkey == (const char *)0) ? "" : pathkey,
        (pathcrl == (const char *)0) ? "" : pathcrl,
        selfsigned,
        (pathcap == (const char *)0) ? "" : pathcap,
        (pathcaf == (const char *)0) ? "" : pathcaf,
        (expected == (const char *)0) ? "" : expected,
        (farend == (const char *)0) ? "" : farend,
        (nearend == (const char *)0) ? "" : nearend,
        (role == CLIENT) ? "Client" : (role == SERVER) ? "Server" : "Unknown");

    buffer = (uint8_t *)malloc(bufsize);
    assert(buffer != (uint8_t *)0);

    assert(farend != (const char *)0);
    rc = diminuto_ipc_endpoint(farend, &farendpoint);
    assert(rc == 0);
    switch (farendpoint.type) {
    case AF_INET:
        assert(!diminuto_ipc4_is_unspecified(&farendpoint.ipv4));
        break;
    case AF_INET6:
        assert(!diminuto_ipc6_is_unspecified(&farendpoint.ipv6));
        break;
    default:
        assert((farendpoint.type == AF_INET) || (farendpoint.type == AF_INET6));
        break;
    }

    assert(nearend != (const char *)0);
    rc = diminuto_ipc_endpoint(nearend, &nearendpoint);
    assert(rc == 0);
    switch (nearendpoint.type) {
    case AF_INET:
        assert(diminuto_ipc4_is_unspecified(&nearendpoint.ipv4));
        break;
    case AF_INET6:
        assert(diminuto_ipc6_is_unspecified(&nearendpoint.ipv6));
        break;
    default:
        assert((farendpoint.type == AF_INET) || (farendpoint.type == AF_INET6));
        break;
    }

    switch (role) {
    case CLIENT:
        assert(farendpoint.tcp != 0);
        assert(nearendpoint.udp != 0);
        break;
    case SERVER:
        assert(farendpoint.udp != 0);
        assert(nearendpoint.tcp != 0);
        break;
    default:
        assert(role != UNKNOWN);
        break;
    }

    rc = diminuto_hangup_install(!0);
    assert(rc == 0);

    diminuto_mux_init(&mux);

    codex_set_self_signed_certificates(selfsigned ? 1 : 0);

    rc = codex_initialize(pathdhf, pathcrl);
    assert(rc == 0);

    ctx = codex_client_context_new(pathcaf, pathcap, pathcrt, pathkey);
    assert(ctx != (SSL_CTX *)0);

    /**/

    diminuto_mux_fini(&mux);

    free(buffer);

    DIMINUTO_LOG_INFORMATION("%s: END\n", program);

    exit(0);
}
