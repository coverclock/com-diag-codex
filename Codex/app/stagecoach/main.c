/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2022-2023 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 * This program provides an SSL tunnel between two UDP endpoints
 * while preserving datagram boundaries. It is agnostic as to the
 * data being passed via UDP, but it was written specifically to
 * provide this capability for the gpstool utility that is part of
 * the Hazer project (https://github.com/coverclock/com-diag-hazer).
 * gpstool can forward NMEA sentences, RTK messages, or CSV packets
 * to UDP port, but lacks any authentication or encryption capability.
 * In this manner, this utility serves as a proxy for the server on
 * the client end, and proxy for the client on the server end.
 *
 * I really really wanted NOT to have to write this program. I felt
 * that I should be able to script it using some combination of maybe
 * socat and ssh. But I didn't see a way to preserve the record boundaries
 * of datagrams as the data propagates across the SSL tunnel. Some web
 * searching didn't change my mind, despite the claims of many commenters;
 * the solutions I saw worked most of the time by coincidence, in my
 * opinion.
 *
 * WORK IN PROGRESS
 */

#include "com/diag/codex/codex.h"
#include "com/diag/diminuto/diminuto_assert.h"
#include "com/diag/diminuto/diminuto_core.h"
#include "com/diag/diminuto/diminuto_delay.h"
#include "com/diag/diminuto/diminuto_fd.h"
#include "com/diag/diminuto/diminuto_frequency.h"
#include "com/diag/diminuto/diminuto_hangup.h"
#include "com/diag/diminuto/diminuto_ipc4.h"
#include "com/diag/diminuto/diminuto_ipc6.h"
#include "com/diag/diminuto/diminuto_log.h"
#include "com/diag/diminuto/diminuto_minmaxof.h"
#include "com/diag/diminuto/diminuto_mux.h"
#include "com/diag/diminuto/diminuto_terminator.h"
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include "../src/codex.h"
#include "client.h"
#include "globals.h"
#include "protocols.h"
#include "server.h"
#include "types.h"


int main(int argc, char * argv[])
{
    int opt = '\0';
    extern char * optarg;
    char * endptr = (char *)0;
    const char * bytes = (const char *)0;
    const char * expected = (const char *)0;
    const char * farend = (const char *)0;
    const char * nearend = (const char *)0;
    const char * pathcaf = (const char *)0;
    const char * pathcap = (const char *)0;
    const char * pathcrl = (const char *)0;
    const char * pathcrt = (const char *)0;
    const char * pathdhf = (const char *)0;
    const char * pathkey = (const char *)0;
    const char * seconds = (const char *)0;
    role_t role = INVALID;
    bool selfsigned = true;
    size_t bufsize = 65527; /* max(datagram)=(2^16-1)-8 */
    unsigned long timeout = -1;
    diminuto_sticks_t ticks = -1;
    int rc = -1;
    diminuto_ipc_endpoint_t farendpoint = { 0 };
    diminuto_ipc_endpoint_t nearendpoint = { 0 };
    codex_context_t * ctx = (codex_context_t *)0;
    codex_connection_t * ssl = (codex_connection_t *)0;
    codex_rendezvous_t * bio = (codex_rendezvous_t *)0;
    protocol_t nearendtype = OTHER;
    protocol_t farendtype = OTHER;
    protocol_t biotype = OTHER;
    protocol_t ssltype = OTHER;
    protocol_t udptype = OTHER;
    int biofd = -1;
    int sslfd = -1;
    int udpfd = -1;
    int muxfd = -1;
    diminuto_mux_t mux = { 0 };
    status_t status = UNKNOWN;
    address_t address = { 0, };
    port_t port = 0;
    address_t serviceaddress = { 0, };
    port_t serviceport = 0;
    int fds = 0;
    int xc = 0;

    /*
     * BEGIN
     */

    (void)diminuto_core_enable();

    diminuto_log_setmask();

    /*
     * PARSING
     */

    program = ((program = strrchr(argv[0], '/')) == (char *)0) ? argv[0] : program + 1;

    while ((opt = getopt(argc, argv, "C:D:E:K:L:P:R:b:cf:n:rst:v?")) >= 0) {

        switch (opt) {

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

        case 'P':
        	pathcap = (*optarg != '\0') ? optarg : (const char *)0;
        	break;

        case 'R':
        	pathcaf = (*optarg != '\0') ? optarg : (const char *)0;
        	break;

        case 'b':
            bytes = optarg;
        	break;

        case 'c':
            role = CLIENT;
            break;

        case 'f':
        	farend = optarg;
        	break;

        case 'n':
        	nearend = optarg;
        	break;

        case 'r':
        	selfsigned = false;
        	break;

        case 's':
            role = SERVER;
            break;

        case 't':
            seconds = optarg;
            break;

        case '?':
        	fprintf(stderr, "usage: %s [ -C CERTIFICATEFILE ] [ -D DHPARMSFILE ] [ -E EXPECTEDDOMAIN ] [ -K PRIVATEKEYFILE ] [ -L REVOCATIONFILE ] [ -P CERTIFICATESPATH ] [ -R ROOTFILE ] [ -b BYTES ] [ -f FARENDPOINT ] [ -n NEARENDPOINT ] [ -r ] [ -t SECONDS ] [ -c | -s ]\n", program);
            return 1;
            break;

        }

    }

	DIMINUTO_LOG_INFORMATION("%s: %s BEGIN B=\"%s\" C=\"%s\" D=\"%s\" K=\"%s\" L=\"%s\" P=\"%s\" R=\"%s\" e=\"%s\" f=\"%s\" n=\"%s\" r=%d t=\"%s\" %c=%d\n",
        program,
        (role == CLIENT) ? "client" : (role == SERVER) ? "server" : "unknown",
        (bytes == (const char *)0) ? "" : bytes,
        (pathcrt == (const char *)0) ? "" : pathcrt,
        (pathdhf == (const char *)0) ? "" : pathdhf,
        (pathkey == (const char *)0) ? "" : pathkey,
        (pathcrl == (const char *)0) ? "" : pathcrl,
        (pathcap == (const char *)0) ? "" : pathcap,
        (pathcaf == (const char *)0) ? "" : pathcaf,
        (expected == (const char *)0) ? "" : expected,
        (farend == (const char *)0) ? "" : farend,
        (nearend == (const char *)0) ? "" : nearend,
        selfsigned,
        (seconds == (const char *)0) ? "" : seconds,
        role, !0);

    diminuto_assert((role == SERVER) || (role == CLIENT));

    bufsize = strtoul(bytes, &endptr, 0);
    diminuto_assert((endptr != (const char *)0) && (*endptr == '\0') && (bufsize > 0));

    timeout = strtoul(seconds, &endptr, 0);
    diminuto_assert((endptr != (const char *)0) && (*endptr == '\0') && (seconds > 0));
    ticks = diminuto_frequency_units2ticks(timeout, 1 /* Hz */);
    
    /*
     * INITIALIZATING
     */

    rc = diminuto_hangup_install(!0);
    diminuto_assert(rc == 0);

    rc = diminuto_terminator_install(!0);
    diminuto_assert(rc == 0);

    diminuto_mux_init(&mux);

    /*
     * INTERPRETING
     */

    diminuto_assert(farend != (const char *)0);
    rc = diminuto_ipc_endpoint(farend, &farendpoint);
    diminuto_assert(rc == 0);
    switch (farendpoint.type) {

    case DIMINUTO_IPC_TYPE_IPV4:
        diminuto_assert(!diminuto_ipc4_is_unspecified(&farendpoint.ipv4));
        farendtype = IPV4;
        break;

    case DIMINUTO_IPC_TYPE_IPV6:
        diminuto_assert(!diminuto_ipc6_is_unspecified(&farendpoint.ipv6));
        farendtype = IPV6;
        break;

    default:
        diminuto_assert(false);
        break;
    }

    diminuto_assert(nearend != (const char *)0);
    rc = diminuto_ipc_endpoint(nearend, &nearendpoint);
    diminuto_assert(rc == 0);
    switch (nearendpoint.type) {

    case DIMINUTO_IPC_TYPE_IPV4:
        diminuto_assert(diminuto_ipc4_is_unspecified(&nearendpoint.ipv4) || diminuto_ipc4_is_loopback(&nearendpoint.ipv4));
        nearendtype = IPV4;
        break;

    case DIMINUTO_IPC_TYPE_IPV6:
        diminuto_assert(diminuto_ipc6_is_unspecified(&nearendpoint.ipv6) || diminuto_ipc6_is_loopback(&nearendpoint.ipv6));
        nearendtype = IPV6;
        break;

    default:
        diminuto_assert(false);
        break;
    }

    codex_set_self_signed_certificates(selfsigned ? 1 : 0);

    rc = codex_initialize(pathdhf, pathcrl);
    diminuto_assert(rc == 0);

    /*
     * CONNECTING
     */

    switch (role) {

    case CLIENT:

        /*
         * CLIENT UDP
         */

        udptype = nearendtype;
        diminuto_assert(nearendpoint.udp != 0);
        udpfd = rendezvous_service(udptype, nearendpoint.udp);
        diminuto_assert(udpfd >= 0);

        rc = connection_nearend(udptype, udpfd, &address, &port);
        diminuto_assert(rc >= 0);
        DIMINUTO_LOG_INFORMATION("%s: client udp (%d) near end %s\n", program, udpfd, address2string(udptype, &address, port));

        rc = diminuto_mux_register_read(&mux, udpfd);
        diminuto_assert(rc >= 0);

        /*
         * CLIENT SSL
         */

        ssltype = farendtype;
        diminuto_assert(farendpoint.tcp != 0);
        ctx = codex_client_context_new(pathcaf, pathcap, pathcrt, pathkey);
        diminuto_assert(ctx != (codex_context_t *)0);
        ssl = codex_client_connection_new(ctx, farend);
        diminuto_assert(ssl != (codex_connection_t *)0);
        diminuto_expect(!codex_connection_is_server(ssl));
        sslfd = codex_connection_descriptor(ssl);
        diminuto_assert(sslfd >= 0);

        rc = connection_nearend(ssltype, sslfd, &address, &port);
        diminuto_assert(rc >= 0);
        DIMINUTO_LOG_INFORMATION("%s: client ssl (%d) near end %s\n", program, sslfd, address2string(ssltype, &address, port));
        rc = connection_farend(ssltype, sslfd, &address, &port);
        diminuto_assert(rc >= 0);
        DIMINUTO_LOG_INFORMATION("%s: client ssl (%d) far end %s\n", program, sslfd, address2string(ssltype, &address, port));
        
        rc = diminuto_mux_register_read(&mux, sslfd);
        diminuto_assert(rc >= 0);
        break;

    case SERVER:

        /*
         * SERVER BIO
         */

        biotype = nearendtype;
        ssltype = nearendtype;
        diminuto_assert(nearendpoint.tcp != 0);
        ctx = codex_server_context_new(pathcaf, pathcap, pathcrt, pathkey);
        diminuto_assert(ctx != (codex_context_t *)0);
        bio = codex_server_rendezvous_new(nearend);
        diminuto_assert(bio != (codex_rendezvous_t *)0);
        biofd = codex_rendezvous_descriptor(bio);
        diminuto_assert(biofd >= 0);

        rc = connection_nearend(biotype, biofd, &address, &port);
        DIMINUTO_LOG_INFORMATION("%s: server bio (%d) near end %s\n", program, biofd, address2string(udptype, &address, port));

        rc = diminuto_mux_register_accept(&mux, biofd);
        diminuto_assert(rc >= 0);

        /*
         * SERVER UDP
         */

        udptype = farendtype;
        diminuto_assert(farendpoint.udp != 0);
        udpfd = rendezvous_ephemeral(udptype);
        diminuto_assert(udpfd >= 0);

        rc = connection_nearend(udptype, udpfd, &address, &port);
        diminuto_assert(rc >= 0);
        DIMINUTO_LOG_INFORMATION("%s: server udp (%d) near end %s\n", program, udpfd, address2string(udptype, &address, port));

        switch (farendtype) {
        case IPV4:
            serviceaddress.address4 = farendpoint.ipv4;
            break;
        case IPV6:
            serviceaddress.address6 = farendpoint.ipv6;
            break;
        default:
            diminuto_assert(false);
            break;
        }
        serviceport = farendpoint.udp;
        DIMINUTO_LOG_INFORMATION("%s: server udp (%d) far end %s\n", program, udpfd, address2string(udptype, &serviceaddress, serviceport));

        rc = diminuto_mux_register_read(&mux, udpfd);
        diminuto_assert(rc >= 0);
        break;

    default:
        diminuto_assert(false);
        break;

    }

    /*
     * WORK LOOP
     */

    while (true) {

        if (diminuto_terminator_check()) {
            DIMINUTO_LOG_NOTICE("%s: SIGTERM\n", program);
            break;
        }

        if (diminuto_hangup_check()) {
            DIMINUTO_LOG_NOTICE("%s: SIGHUP\n", program);
            /* Unimplemented. */
            diminuto_yield();
            continue;
        }

        fds = diminuto_mux_wait(&mux, ticks);
        diminuto_assert((fds >= 0) || ((fds < 0) && (errno == EINTR)));

        /*
         * SERVER SSL
         */

        if ((fds > 0) && (role == SERVER)) {
            muxfd = diminuto_mux_ready_accept(&mux);
            if ((muxfd >= 0) && (muxfd == biofd)) {
                diminuto_assert(ssl == (codex_connection_t *)0);
                ssl = codex_server_connection_new(ctx, bio);
                diminuto_assert(ssl != (codex_connection_t *)0);
                diminuto_expect(codex_connection_is_server(ssl));
                diminuto_assert(sslfd < 0);
                sslfd = codex_connection_descriptor(ssl);
                diminuto_assert(sslfd >= 0);

                rc = connection_nearend(ssltype, sslfd, &address, &port);
                diminuto_assert(rc >= 0);
                DIMINUTO_LOG_NOTICE("%s: server ssl (%d) near end %s\n", program, udpfd, address2string(ssltype, &address, port));
                rc = connection_farend(ssltype, sslfd, &address, &port);
                diminuto_assert(rc >= 0);
                DIMINUTO_LOG_NOTICE("%s: server ssl (%d) far end %s\n", program, udpfd, address2string(ssltype, &address, port));

                rc = diminuto_mux_register_read(&mux, sslfd);
                diminuto_assert(rc >= 0);
            }
        }

        if (ssl != (codex_connection_t *)0) {
            switch (role) {
            case CLIENT:
                status = client(fds, &mux, udptype, udpfd, ssl, bufsize, expected);
                break;
            case SERVER:
                status = server(fds, &mux, udptype, udpfd, &serviceaddress, serviceport, ssl, bufsize, expected);
                break;
            default:
                diminuto_assert(false);
                break;
            }
            if (status != CONTINUE) {
                break;
            }
        }

    }

    /*
     * DISCONNECTING
     */

    if (udpfd >= 0) {
        rc = diminuto_ipc_close(udpfd);
        diminuto_expect(rc >= 0);
        rc = diminuto_mux_unregister_read(&mux, udpfd);
        diminuto_expect(rc >= 0);
        udpfd = -1;
    }

    if (ssl != (codex_connection_t *)0) {
        rc = codex_connection_close(ssl);
        diminuto_expect(rc >= 0);
        ssl = codex_connection_free(ssl);
        diminuto_expect(ssl == (codex_connection_t *)0);
        ssl = (codex_connection_t *)0;
    }

    if (sslfd >= 0) {
        rc = diminuto_ipc_close(sslfd);
        diminuto_expect(rc < 0);
        rc = diminuto_mux_unregister_read(&mux, sslfd);
        diminuto_expect(rc >= 0);
        sslfd = -1;
    }

    /*
     * FINALIZATING
     */

    ctx = codex_context_free(ctx);
    diminuto_expect(ctx == (codex_context_t *)0);
    ctx = (codex_context_t *)0;

    diminuto_mux_fini(&mux);

    /*
     * END
     */

    DIMINUTO_LOG_INFORMATION("%s: END %d\n", program, xc);

    exit(xc);
}
