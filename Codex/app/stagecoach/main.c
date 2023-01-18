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
 * that I should be able to script it using some combination of maybe
 * socat and ssh. But I didn't see a way to preserve the record boundaries
 * of datagrams as the data propagates across the SSL tunnel. Some web
 * searching didn't change my mind, despite the claims of many commenters;
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
#include "com/diag/diminuto/diminuto_types.h"
#include "com/diag/codex/codex.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "../src/codex.h"

typedef enum Role { UNKNOWN = 0, CLIENT = 1, SERVER = 2, } role_t;

typedef uint16_t length_t;

static const char * program = (const char *)0;
static const char * nearend = (const char *)0;
static const char * farend = (const char *)0;
static const char * expected = (const char *)0;
static const char * pathcaf = (const char *)0;
static const char * pathcap = (const char *)0;
static const char * pathcrl = (const char *)0;
static const char * pathcrt = (const char *)0;
static const char * pathkey = (const char *)0;
static const char * pathdhf = (const char *)0;
static size_t bufsize = 65527; /* max(datagram)=(2^16-1)-8 */
static role_t role = UNKNOWN;
static bool selfsigned = true;

int main(int argc, char * argv[])
{
    int opt = '\0';
    extern char * optarg;
    char * endptr = (char *)0;
    int rc = -1;
    length_t length = 0;
    uint8_t * buffer = (uint8_t *)0;
    diminuto_mux_t mux = { 0 };
    diminuto_ipc_endpoint_t farendpoint = { 0 };
    diminuto_ipc_endpoint_t nearendpoint = { 0 };
    codex_context_t * ctx = (codex_context_t *)0;
    codex_connection_t * ssl = (codex_connection_t *)0;
    codex_rendezvous_t * bio = (codex_rendezvous_t *)0;
    int biofd = -1;
    int udpfd = -1;
    int sslfd = -1;
    int readyfd = -1;
    diminuto_ipv4_t ipv4address = 0;
    diminuto_ipv6_t ipv6address = { 0, };
    diminuto_port_t port = 0;
    diminuto_ipv4_buffer_t ipv4string = { '\0', };
    diminuto_ipv6_buffer_t ipv6string = { '\0', };

    /*
     * BEGIN
     */

    (void)diminuto_core_enable();

    diminuto_log_setmask();

    /*
     * PARSE
     */

    program = ((program = strrchr(argv[0], '/')) == (char *)0) ? argv[0] : program + 1;

    while ((opt = getopt(argc, argv, "B:C:D:E:K:L:MP:R:cf:mn:sv?")) >= 0) {

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

        case 'E':
            expected = (*optarg != '\0') ? optarg : (const char *)0;
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

        case '?':
        	fprintf(stderr, "usage: %s [ -B BUFSIZE ] [ -C CERTIFICATEFILE ] [ -D DHPARMSFILE ] [ -E EXPECTEDDOMAIN ] [ -K PRIVATEKEYFILE ] [ -L REVOCATIONFILE ] [ -P CERTIFICATESPATH ] [ -R ROOTFILE ] [ -f FAREND ] [ -n NEAREND ] [ -M | -m ] [ -c(lient) | -s(erver) ]\n", program);
            return 1;
            break;

        }

    }

	DIMINUTO_LOG_INFORMATION("%s: BEGIN B=%zu C=\"%s\" D=\"%s\" K=\"%s\" L=\"%s\" M=%d P=\"%s\" R=\"%s\" c=%d e=\"%s\" f=\"%s\" m=%d n=\"%s\" s=%d\n",
        program,
        bufsize,
        (pathcrt == (const char *)0) ? "" : pathcrt,
        (pathdhf == (const char *)0) ? "" : pathdhf,
        (pathkey == (const char *)0) ? "" : pathkey,
        (pathcrl == (const char *)0) ? "" : pathcrl,
        selfsigned,
        (pathcap == (const char *)0) ? "" : pathcap,
        (pathcaf == (const char *)0) ? "" : pathcaf,
        (role == CLIENT),
        (expected == (const char *)0) ? "" : expected,
        (farend == (const char *)0) ? "" : farend,
        !selfsigned,
        (nearend == (const char *)0) ? "" : nearend,
        (role == SERVER));

    /*
     * INITIALIZATING
     */

    rc = diminuto_hangup_install(!0);
    diminuto_assert(rc == 0);

    rc = diminuto_terminator_install(!0);
    diminuto_assert(rc == 0);

    diminuto_mux_init(&mux);

    diminuto_assert(farend != (const char *)0);
    rc = diminuto_ipc_endpoint(farend, &farendpoint);
    diminuto_assert(rc == 0);
    switch (farendpoint.type) {

    case DIMINUTO_IPC_TYPE_IPV4:
        diminuto_assert(!diminuto_ipc4_is_unspecified(&farendpoint.ipv4));
        break;

    case DIMINUTO_IPC_TYPE_IPV6:
        diminuto_assert(!diminuto_ipc6_is_unspecified(&farendpoint.ipv6));
        break;

    default:
        diminuto_assert((farendpoint.type == DIMINUTO_IPC_TYPE_IPV4) || (farendpoint.type == DIMINUTO_IPC_TYPE_IPV6));
        break;
    }

    diminuto_assert(nearend != (const char *)0);
    rc = diminuto_ipc_endpoint(nearend, &nearendpoint);
    diminuto_assert(rc == 0);
    switch (nearendpoint.type) {

    case DIMINUTO_IPC_TYPE_IPV4:
        diminuto_assert(diminuto_ipc4_is_unspecified(&nearendpoint.ipv4) || diminuto_ipc4_is_loopback(&nearendpoint.ipv4));
        break;

    case DIMINUTO_IPC_TYPE_IPV6:
        diminuto_assert(diminuto_ipc6_is_unspecified(&nearendpoint.ipv6) || diminuto_ipc6_is_loopback(&nearendpoint.ipv6));
        break;

    default:
        diminuto_assert((farendpoint.type == DIMINUTO_IPC_TYPE_IPV4) || (farendpoint.type == DIMINUTO_IPC_TYPE_IPV6));
        break;
    }

    /*
     * ALLOCATING
     */

    buffer = (uint8_t *)malloc(bufsize);
    diminuto_assert(buffer != (uint8_t *)0);

    codex_set_self_signed_certificates(selfsigned ? 1 : 0);

    rc = codex_initialize(pathdhf, pathcrl);
    diminuto_assert(rc == 0);

    /*
     * CONNECTING
     */

    switch (role) {

    case CLIENT:

        /*
         * CLIENT FAR END (SSL)
         */

        diminuto_assert(farendpoint.tcp != 0);
        ctx = codex_client_context_new(pathcaf, pathcap, pathcrt, pathkey);
        diminuto_assert(ctx != (codex_context_t *)0);
        ssl = codex_client_connection_new(ctx, farend);
        diminuto_assert(ssl != (codex_connection_t *)0);
        diminuto_expect(!codex_connection_is_server(ssl));
        sslfd = codex_connection_descriptor(ssl);
        diminuto_assert(sslfd >= 0);

        switch (farendpoint.type) {
        case DIMINUTO_IPC_TYPE_IPV4:
            rc = diminuto_ipc4_nearend(sslfd, &ipv4address, &port);
            diminuto_assert(rc >= 0);
            DIMINUTO_LOG_INFORMATION("%s: client ssl [%d] near end %s:%d\n", program, sslfd, diminuto_ipc4_address2string(ipv4address, ipv4string, sizeof(ipv4string)), port);
            rc = diminuto_ipc4_farend(sslfd, &ipv4address, &port);
            diminuto_assert(rc >= 0);
            DIMINUTO_LOG_INFORMATION("%s: client ssl [%d] far end %s:%d\n", program, sslfd, diminuto_ipc4_address2string(ipv4address, ipv4string, sizeof(ipv4string)), port);
            break;
        case DIMINUTO_IPC_TYPE_IPV6:
            rc = diminuto_ipc6_nearend(sslfd, &ipv6address, &port);
            diminuto_assert(rc >= 0);
            DIMINUTO_LOG_INFORMATION("%s: client ssl [%d] near end [%s]:%d\n", program, sslfd, diminuto_ipc6_address2string(ipv6address, ipv6string, sizeof(ipv6string)), port);
            rc = diminuto_ipc6_farend(sslfd, &ipv6address, &port);
            diminuto_assert(rc >= 0);
            DIMINUTO_LOG_INFORMATION("%s: client ssl [%d] far end [%s]:%d\n", program, sslfd, diminuto_ipc6_address2string(ipv6address, ipv6string, sizeof(ipv6string)), port);
            break;
        default:
            break;
        }

        /*
         * CLIENT NEAR END (SERVICE)
         */

        diminuto_assert(nearendpoint.udp != 0);
        switch (nearendpoint.type) {
        case DIMINUTO_IPC_TYPE_IPV4:
            udpfd = diminuto_ipc4_datagram_peer(nearendpoint.udp);
            diminuto_assert(udpfd >= 0);
            rc = diminuto_ipc4_nearend(udpfd, &ipv4address, &port);
            diminuto_assert(rc >= 0);
            DIMINUTO_LOG_INFORMATION("%s: client udp [%d] near end %s:%d\n", program, udpfd, diminuto_ipc4_address2string(ipv4address, ipv4string, sizeof(ipv4string)), port);
            rc = diminuto_ipc4_farend(udpfd, &ipv4address, &port);
            diminuto_assert(rc >= 0);
            DIMINUTO_LOG_INFORMATION("%s: client udp [%d] far end %s:%d\n", program, udpfd, diminuto_ipc4_address2string(ipv4address, ipv4string, sizeof(ipv4string)), port);
            break;
        case DIMINUTO_IPC_TYPE_IPV6:
            udpfd = diminuto_ipc6_datagram_peer(nearendpoint.udp);
            diminuto_assert(udpfd >= 0);
            rc = diminuto_ipc6_nearend(udpfd, &ipv6address, &port);
            diminuto_assert(rc >= 0);
            DIMINUTO_LOG_INFORMATION("%s: client udp [%d] near end [%s]:%d\n", program, udpfd, diminuto_ipc6_address2string(ipv6address, ipv6string, sizeof(ipv6string)), port);
            rc = diminuto_ipc6_farend(udpfd, &ipv6address, &port);
            diminuto_assert(rc >= 0);
            DIMINUTO_LOG_INFORMATION("%s: client udp [%d] far end [%s]:%d\n", program, udpfd, diminuto_ipc6_address2string(ipv6address, ipv6string, sizeof(ipv6string)), port);
            break;
        default:
            diminuto_assert((nearendpoint.type == DIMINUTO_IPC_TYPE_IPV4) || (nearendpoint.type == DIMINUTO_IPC_TYPE_IPV6));
            break;
        }

        break;

    case SERVER:

        /*
         * SERVER FAR END (EPHEMERAL)
         */

        diminuto_assert(farendpoint.udp != 0);
        switch (farendpoint.type) {
        case DIMINUTO_IPC_TYPE_IPV4:
            udpfd = diminuto_ipc4_datagram_peer(0);
            diminuto_assert(udpfd >= 0);
            rc = diminuto_ipc4_nearend(udpfd, &ipv4address, &port);
            diminuto_assert(rc >= 0);
            DIMINUTO_LOG_INFORMATION("%s: server udp [%d] near end %s:%d\n", program, udpfd, diminuto_ipc4_address2string(ipv4address, ipv4string, sizeof(ipv4string)), port);
            rc = diminuto_ipc4_farend(udpfd, &ipv4address, &port);
            diminuto_assert(rc >= 0);
            DIMINUTO_LOG_INFORMATION("%s: server udp [%d] far end %s:%d\n", program, udpfd, diminuto_ipc4_address2string(ipv4address, ipv4string, sizeof(ipv4string)), port);
            break;
        case DIMINUTO_IPC_TYPE_IPV6:
            udpfd = diminuto_ipc6_datagram_peer(0);
            diminuto_assert(udpfd >= 0);
            rc = diminuto_ipc6_nearend(udpfd, &ipv6address, &port);
            diminuto_assert(rc >= 0);
            DIMINUTO_LOG_INFORMATION("%s: server udp [%d] near end [%s]:%d\n", program, udpfd, diminuto_ipc6_address2string(ipv6address, ipv6string, sizeof(ipv6string)), port);
            rc = diminuto_ipc6_farend(udpfd, &ipv6address, &port);
            diminuto_assert(rc >= 0);
            DIMINUTO_LOG_INFORMATION("%s: server udp [%d] far end [%s]:%d\n", program, udpfd, diminuto_ipc6_address2string(ipv6address, ipv6string, sizeof(ipv6string)), port);
            break;
        default:
            break;
        }

        /*
         * SERVER NEAR END (BIO)
         */

        diminuto_assert(nearendpoint.tcp != 0);
        ctx = codex_server_context_new(pathcaf, pathcap, pathcrt, pathkey);
        diminuto_assert(ctx != (codex_context_t *)0);
        bio = codex_server_rendezvous_new(nearend);
        diminuto_assert(bio != (codex_rendezvous_t *)0);
        biofd = codex_rendezvous_descriptor(bio);
        diminuto_assert(biofd >= 0);

        switch (nearendpoint.type) {
        case DIMINUTO_IPC_TYPE_IPV4:
            rc = diminuto_ipc4_nearend(biofd, &ipv4address, &port);
            diminuto_assert(rc >= 0);
            DIMINUTO_LOG_INFORMATION("%s: server bio [%d] near end %s:%d\n", program, biofd, diminuto_ipc4_address2string(ipv4address, ipv4string, sizeof(ipv4string)), port);
            rc = diminuto_ipc4_farend(biofd, &ipv4address, &port);
            diminuto_assert(rc >= 0);
            DIMINUTO_LOG_INFORMATION("%s: server bio [%d] far end %s:%d\n", program, biofd, diminuto_ipc4_address2string(ipv4address, ipv4string, sizeof(ipv4string)), port);
            break;
        case DIMINUTO_IPC_TYPE_IPV6:
            rc = diminuto_ipc6_nearend(biofd, &ipv6address, &port);
            diminuto_assert(rc >= 0);
            DIMINUTO_LOG_INFORMATION("%s: server bio [%d] near end [%s]:%d\n", program, biofd, diminuto_ipc6_address2string(ipv6address, ipv6string, sizeof(ipv6string)), port);
            rc = diminuto_ipc6_farend(biofd, &ipv6address, &port);
            diminuto_assert(rc >= 0);
            DIMINUTO_LOG_INFORMATION("%s: server bio [%d] far end [%s]:%d\n", program, biofd, diminuto_ipc6_address2string(ipv6address, ipv6string, sizeof(ipv6string)), port);
            break;
        default:
            break;
        }

        break;

    default:

        diminuto_assert(role != UNKNOWN);

        break;

    }

    /*
     * WORK
     */

    /*
     * DISCONNECTING
     */

    rc = diminuto_ipc_close(udpfd);
    diminuto_expect(rc >= 0);
    udpfd = -1;

    rc = codex_connection_close(ssl);
    diminuto_expect(rc >= 0);

    /*
     * DEALLOCATING
     */

    ssl = codex_connection_free(ssl);
    diminuto_expect(ssl == (codex_connection_t *)0);

    ctx = codex_context_free(ctx);
    diminuto_expect(ctx == (codex_context_t *)0);

    free(buffer);

    /*
     * FINALIZATING
     */

    diminuto_mux_fini(&mux);

    /*
     * END
     */

    DIMINUTO_LOG_INFORMATION("%s: END\n", program);

    exit(0);
}
