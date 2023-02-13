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
#include "client.h"
#include "globals.h"
#include "protocols.h"
#include "server.h"
#include "types.h"


int main(int argc, char * argv[])
{
    extern char * optarg;
    int opt = '\0';
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
    const char * delay = (const char *)0;
    const char * timeout = (const char *)0;
    role_t role = INVALID;
    bool selfsigned = true; /* Allow self-signed certificates by default. */
    size_t bufsize = 65527; /* max(datagram)=(2^16-1)-8 */
    unsigned long delaymilliseconds = 10000;
    unsigned long timeoutmilliseconds = 250;
    diminuto_sticks_t delayticks = 0;
    diminuto_sticks_t timeoutticks = 0;
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
    int acceptfd = -1;
    diminuto_mux_t mux = { 0 };
    status_t status = UNKNOWN;
    address_t address = { 0, };
    port_t port = 0;
    address_t serviceaddress = { 0, };
    port_t serviceport = 0;
    int fds = 0;
    bool done = false;

    /*
     * BEGIN
     */

    (void)diminuto_core_enable();

    diminuto_log_setmask();

    /*
     * PARSING
     */

    program = ((program = strrchr(argv[0], '/')) == (char *)0) ? argv[0] : program + 1;

    while ((opt = getopt(argc, argv, "C:D:E:K:L:P:R:b:cd:f:n:rst:v?")) >= 0) {

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

        case 'd':
            delay = optarg;
            break;

        case 'f':
            farend = optarg;
            break;

        case 'n':
            nearend = optarg;
            break;

        case 'r':
            selfsigned = false; /* Require certificates signed by a CA. */
            break;

        case 's':
            role = SERVER;
            break;

        case 't':
            timeout = optarg;
            break;

        case '?':
            fprintf(stderr, "usage: %s [ -C CERTIFICATEFILE ] [ -D DHPARMSFILE ] [ -E EXPECTEDDOMAIN ] [ -K PRIVATEKEYFILE ] [ -L REVOCATIONFILE ] [ -P CERTIFICATESPATH ] [ -R ROOTFILE ] [ -b BYTES ] [ -d MILLISECONDS ] [ -f FARENDPOINT ] [ -n NEARENDPOINT ] [ -r ] [ -t MILLISECONDS ] [ -c | -s ]\n", program);
            exit(1);
            break;

        }

    }

    DIMINUTO_LOG_INFORMATION("%s: %s begin B=\"%s\" C=\"%s\" D=\"%s\" K=\"%s\" L=\"%s\" P=\"%s\" R=\"%s\" d=\"%s\" e=\"%s\" f=\"%s\" n=\"%s\" r=%d t=\"%s\" %c=%d\n",
        program,
        (role == CLIENT) ? "client" : (role == SERVER) ? "server" : "unknown",
        (bytes == (const char *)0) ? "" : bytes,
        (pathcrt == (const char *)0) ? "" : pathcrt,
        (pathdhf == (const char *)0) ? "" : pathdhf,
        (pathkey == (const char *)0) ? "" : pathkey,
        (pathcrl == (const char *)0) ? "" : pathcrl,
        (pathcap == (const char *)0) ? "" : pathcap,
        (pathcaf == (const char *)0) ? "" : pathcaf,
        (delay == (const char *)0) ? "" : delay,
        (expected == (const char *)0) ? "" : expected,
        (farend == (const char *)0) ? "" : farend,
        (nearend == (const char *)0) ? "" : nearend,
        !selfsigned,
        (timeout == (const char *)0) ? "" : timeout,
        role, !0);

    diminuto_assert((role == SERVER) || (role == CLIENT));

    if (bytes != (const char *)0) {
        bufsize = strtoul(bytes, &endptr, 0);
        diminuto_assert((endptr != (const char *)0) && (*endptr == '\0') && (bufsize > 0));
    }
    DIMINUTO_LOG_INFORMATION("%s: bufsize=%zubytes\n", program, bufsize);

    if (delay != (const char *)0) {
        delaymilliseconds = strtoul(delay, &endptr, 0);
        diminuto_assert((endptr != (const char *)0) && (*endptr == '\0') && (delaymilliseconds > 0));
    }
    delayticks = diminuto_frequency_units2ticks(delaymilliseconds, 1000 /* Hz */);
    DIMINUTO_LOG_INFORMATION("%s: delay=%lums=%lldticks\n", program, delaymilliseconds, (diminuto_lld_t)delayticks);

    if (timeout != (const char *)0) {
        timeoutmilliseconds = strtoul(timeout, &endptr, 0);
        diminuto_assert((endptr != (const char *)0) && (*endptr == '\0') && (timeoutmilliseconds > 0));
    }
    timeoutticks = diminuto_frequency_units2ticks(timeoutmilliseconds, 1000 /* Hz */);
    DIMINUTO_LOG_INFORMATION("%s: timeout=%lums=%lldticks\n", program, timeoutmilliseconds, (diminuto_lld_t)timeoutticks);

    DIMINUTO_LOG_INFORMATION("%s: selfsigned=%d\n", program, selfsigned);

    /*
     * CHECKING
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

    /*
     * If no host is specified for the endpoint, Diminuto assumes IPv6 by default.
     * Using a host name like "0.0.0.0" causes Diminuto to pick IPv4 rather than
     * the default. Note, however, that choosing hostname of "localhost" or
     * "localhost4", while forcing IPv4 as the protocol, also binds the socket to
     * the local host address and prevents remote clients from connecting to it,
     * while using the unspecified ("0.0.0.0") address serves as a wildcard.
     * An IPv6 address of "0:0:0:0:0:0:0:0" (or equivalently "::") similarly
     * forces IPv6 to be selected while not binding the socket to a specific
     * address. Since the implementation doesn't use the address except to
     * select IPv4 or IPv6, we require that it be the "unspecified" address for
     * that protocol. Leaving the address off will result in it being
     * unspecified, but as said above, results in the selection of IPv6 by
     * default. I recommend specifying the appropriate unspecified address
     * specifically (so to speak). And why IPv6 by default? Because IPv6
     * sockets can accept either IPv6 or IPv4 connections, but the opposite
     * is not true.
     */

    diminuto_assert(nearend != (const char *)0);
    rc = diminuto_ipc_endpoint(nearend, &nearendpoint);
    diminuto_assert(rc == 0);
    switch (nearendpoint.type) {

    case DIMINUTO_IPC_TYPE_IPV4:
        diminuto_assert(diminuto_ipc4_is_unspecified(&nearendpoint.ipv4));
        nearendtype = IPV4;
        break;

    case DIMINUTO_IPC_TYPE_IPV6:
        diminuto_assert(diminuto_ipc6_is_unspecified(&nearendpoint.ipv6));
        nearendtype = IPV6;
        break;

    default:
        diminuto_assert(false);
        break;
    }

    switch (role) {

    case CLIENT:
        udptype = nearendtype;
        diminuto_assert(nearendpoint.udp != 0);
        biotype = farendtype;
        ssltype = farendtype;
        diminuto_assert(farendpoint.tcp != 0);
        break;

    case SERVER:
        biotype = nearendtype;
        ssltype = nearendtype;
        diminuto_assert(nearendpoint.tcp != 0);
        udptype = farendtype;
        diminuto_assert(farendpoint.udp != 0);
        break;

    default:
        diminuto_assert(false);
        break;

    }
    
    /*
     * INITIALIZATING
     */

    rc = diminuto_hangup_install(!0);
    diminuto_assert(rc == 0);

    rc = diminuto_terminator_install(!0);
    diminuto_assert(rc == 0);

    diminuto_mux_init(&mux);

    {
        /*
         * Enable (or disable) self-signed certificates using
         * private API. This should be done prior to Codex
         * initialization.
         */
        extern int codex_set_self_signed_certificates(int);
        codex_set_self_signed_certificates(selfsigned);
    }

    rc = codex_initialize(pathdhf, pathcrl);
    diminuto_assert(rc == 0);

    /*
     * SETTING UP
     */

    switch (role) {

    case CLIENT:
        /*
         * CLIENT SSL
         */
        ctx = codex_client_context_new(pathcaf, pathcap, pathcrt, pathkey);
        diminuto_assert(ctx != (codex_context_t *)0);
        switch (biotype) {
        case IPV4:
            address.address4 = farendpoint.ipv4;
            break;
        case IPV6:
            address.address6 = farendpoint.ipv6;
            break;
        default:
            diminuto_assert(false);
            break;
        }
        port = farendpoint.tcp;
        DIMINUTO_LOG_INFORMATION("%s: client bio (-) far end %s\n", program, address2string(biotype, &address, port));
        break;

        break;

    case SERVER:
        /*
         * SERVER BIO
         */
        ctx = codex_server_context_new(pathcaf, pathcap, pathcrt, pathkey);
        diminuto_assert(ctx != (codex_context_t *)0);
        bio = codex_server_rendezvous_new(nearend);
        diminuto_assert(bio != (codex_rendezvous_t *)0);
        biofd = codex_rendezvous_descriptor(bio);
        diminuto_assert(biofd >= 0);
        rc = connection_nearend(biotype, biofd, &address, &port);
        DIMINUTO_LOG_INFORMATION("%s: server bio (%d) near end %s\n", program, biofd, address2string(biotype, &address, port));
        rc = diminuto_mux_register_accept(&mux, biofd);
        diminuto_assert(rc >= 0);
        /*
         * SERVER UDP
         */
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
        break;

    default:
        diminuto_assert(false);
        break;

    }

    /*
     * WORK LOOP
     */

    while (!done) {

        if (diminuto_hangup_check()) {
            DIMINUTO_LOG_NOTICE("%s: SIGHUP\n", program);
            diminuto_yield();
        }

        /*
         * CONNECTING
         */

        switch (role) {

        case CLIENT:
            /*
             * CLIENT UDP
             */
            if (udpfd < 0) {
                udpfd = rendezvous_service(udptype, nearendpoint.udp);
                diminuto_assert(udpfd >= 0);
                rc = connection_nearend(udptype, udpfd, &address, &port);
                diminuto_assert(rc >= 0);
                DIMINUTO_LOG_INFORMATION("%s: client udp (%d) near end %s\n", program, udpfd, address2string(udptype, &address, port));
                rc = diminuto_mux_register_read(&mux, udpfd);
                diminuto_assert(rc >= 0);
            }
            /*
             * CLIENT SSL
             */
            if (sslfd < 0) {
                ssl = codex_client_connection_new(ctx, farend);
                if (ssl != (codex_connection_t *)0) {
                    diminuto_assert(!codex_connection_is_server(ssl));
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
                } else {
                    /*
                     * Retry later.
                     */
                    DIMINUTO_LOG_INFORMATION("%s: client ssl (%d) far end failed\n", program, sslfd);
                    diminuto_delay(delayticks, !0);
                    continue;
                }
            }
            break;

        case SERVER:
            /*
             * SERVER UDP
            */
            if (udpfd < 0) {
                udpfd = rendezvous_ephemeral(udptype);
                diminuto_assert(udpfd >= 0);
                rc = connection_nearend(udptype, udpfd, &address, &port);
                diminuto_assert(rc >= 0);
                DIMINUTO_LOG_INFORMATION("%s: server udp (%d) near end %s\n", program, udpfd, address2string(udptype, &address, port));
                DIMINUTO_LOG_INFORMATION("%s: server udp (%d) far end %s\n", program, udpfd, address2string(udptype, &serviceaddress, serviceport));
                rc = diminuto_mux_register_read(&mux, udpfd);
                diminuto_assert(rc >= 0);
            }
            break;

        default:
            diminuto_assert(false);
            break;

        }

        /*
         * WAITING
         */

        fds = diminuto_mux_wait(&mux, timeoutticks);
        diminuto_assert((fds >= 0) || ((fds < 0) && (errno == EINTR)));
        if (fds != 0) {
            DIMINUTO_LOG_DEBUG("%s: main fds [%d]\n", program, fds);
        }

        /*
         * SERVER SSL
         */

        if (fds <= 0) {
            /* Do nothing. */
        } else if (role != SERVER) {
            /* Do nothing. */
        } else {
            acceptfd = diminuto_mux_ready_accept(&mux);
            if (acceptfd < 0) {
                /* Do nothing. */
            } else if (acceptfd != biofd) {
                /* Do nothing. */
            } else {
                if (sslfd < 0) {
                    diminuto_assert(ssl == (codex_connection_t *)0);
                    ssl = codex_server_connection_new(ctx, bio);
                    diminuto_assert(ssl != (codex_connection_t *)0);
                    diminuto_assert(codex_connection_is_server(ssl));
                    diminuto_assert(sslfd < 0);
                    sslfd = codex_connection_descriptor(ssl);
                    diminuto_assert(sslfd >= 0);
                    rc = connection_nearend(ssltype, sslfd, &address, &port);
                    diminuto_assert(rc >= 0);
                    DIMINUTO_LOG_NOTICE("%s: server ssl (%d) near end %s\n", program, sslfd, address2string(ssltype, &address, port));
                    rc = connection_farend(ssltype, sslfd, &address, &port);
                    diminuto_assert(rc >= 0);
                    DIMINUTO_LOG_NOTICE("%s: server ssl (%d) far end %s\n", program, sslfd, address2string(ssltype, &address, port));
                    rc = diminuto_mux_register_read(&mux, sslfd);
                    diminuto_assert(rc >= 0);
                } else {
                    DIMINUTO_LOG_WARNING("%s: server bio (%d) reject\n", program, sslfd);
                }
                fds -= 0;
            }
        }

        /*
         * PROCESSING
         */

        if (fds <= 0) {
            /* Do nothing. */
        } else if (udpfd < 0) {
            /* Do nothing. */
        } else if (sslfd < 0) {
            /* Do nothing. */
        } else {
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
        }

        /*
         * RECOVERING
         */

        if (diminuto_terminator_check()) {
            DIMINUTO_LOG_NOTICE("%s: SIGTERM\n", program);
            done = true;
        }

        if (done) {
            status = UDPDONE;
        }

        if (status != UDPDONE) {
            /* Do nothing. */
        } else if (udpfd < 0) {
            /* Do nothing. */
        } else {
            (void)diminuto_ipc_close(udpfd);
            (void)diminuto_mux_unregister_read(&mux, udpfd);
            udpfd = -1;
        }

        if (done) {
            status = SSLDONE;
        }

        if (status != SSLDONE) {
            /* Do nothing. */
        } else if (sslfd < 0) {
            /* Do nothing. */
        } else {
            /*
             * May already be closed by virtue of far end closing.
             */
            (void)codex_connection_close(ssl);
            ssl = codex_connection_free(ssl);
            diminuto_assert(ssl == (codex_connection_t *)0);
            ssl = (codex_connection_t *)0;
            (void)diminuto_ipc_close(sslfd);
            (void)diminuto_mux_unregister_read(&mux, sslfd);
            (void)diminuto_mux_unregister_write(&mux, sslfd);
            sslfd = -1;
        }

    }

    /*
     * FINALIZATING
     */

    if (ctx != (codex_context_t *)0) {
        ctx = codex_context_free(ctx);
        diminuto_assert(ctx == (codex_context_t *)0);
        ctx = (codex_context_t *)0;
        if (biofd >= 0) {
            (void)diminuto_ipc_close(biofd);
            (void)diminuto_mux_unregister_accept(&mux, biofd);
            biofd = -1;
        }
    }

    diminuto_mux_fini(&mux);

    /*
     * END
     */

    DIMINUTO_LOG_INFORMATION("%s: end\n", program);

    exit(0);
}
