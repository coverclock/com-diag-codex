/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2023-2025 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 *
 * This application provides a simple connection between an SSL tunnel
 * and standard input and standard output. It can be run in either server
 * or client mode; in server mode it services only a single client at a
 * time. It was directly derived from the source code for the Codex
 * stagecoach application; the code would have probably been a lot cleaner
 * if I'd started from scratch. Remarkably, the most difficult part of
 * getting this to work was establishing the conditions under which each
 * end can exit.
 *
 * NOTES
 *
 * OpenSSL clients and servers have to do a *lot* of talking to each other
 * that all happens "under the hood" with respect to the application:
 * exchanging encryption keys, authenticating each other's certificates, etc.
 *
 * The OpenSSL library doesn't autonomously do any reads or writes. It piggy
 * backs reads and writes when the application does a read or a write. So
 * it has to wait for the application to read if it needs to do a read,
 * and same for a write. Sometimes you get an error return that says "I
 * need to read", or "I need to write", or even "I got nothin'", and you
 * have to accommodate that no matter what your state.
 *
 * The OpenSSL connection object that the application uses to direct reads
 * and writes isn't thread-safe, according to the docs, so you can't just
 * use a reader thread and a writer thread that run concurrently.
 *
 * This makes common approaches, like multiplexing using select(2) (Diminuto
 * Mux), a real challenge, since the system call knows nothing about that's
 * going on in the OpenSSL stack.
 * 
 * You make a mistake, and your application can block on a read
 * indefinitely. Sometimes the answer to that is to keep a flow of "bit
 * bucket" writes going; I got that solution working, but it's not
 * practical for applications using limited or expensive bandwidth WANs.
 */

#include "com/diag/codex/codex.h"
#include "com/diag/diminuto/diminuto_assert.h"
#include "com/diag/diminuto/diminuto_core.h"
#include "com/diag/diminuto/diminuto_daemon.h"
#include "com/diag/diminuto/diminuto_delay.h"
#include "com/diag/diminuto/diminuto_fd.h"
#include "com/diag/diminuto/diminuto_fs.h"
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
#include "globals.h"
#include "helpers.h"
#include "readerwriter.h"
#include "types.h"

static const size_t MAXDATAGRAM = 65527; /* max(datagram)=(2^16-1)-8 */

static const char MASKPATH[] = "/var/run";

int main(int argc, char * argv[])
{
    diminuto_path_t maskfile = { '\0', };
    diminuto_fs_type_t filetype = DIMINUTO_FS_TYPE_NONE;
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
    const char * keepalive = (const char *)0;
    role_t role = INVALID;
    bool introduce = false;
    bool selfsigned = true; /* Allow self-signed certificates by default. */
    bool daemonize = false;
    size_t bufsize = MAXDATAGRAM;
    const char * name = (const char *)0;
    unsigned long delaymilliseconds = 5000;
    unsigned long timeoutmilliseconds = 1000;
    signed long keepalivemilliseconds = -1;
    ticks_t delayticks = 0;
    ticks_t timeoutticks = 0;
    sticks_t keepaliveticks = 0;
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
    int biofd = -1;
    int sslfd = -1;
    int inpfd = -1;
    int outfd = -1;
    int acceptfd = -1;
    diminuto_mux_t mux = { 0 };
    status_t status = UNKNOWN;
    address_t address = { 0, };
    port_t port = 0;
    int fds = 0;
    bool done = false;

    /*
     * BEGIN
     */

    (void)diminuto_core_enable();

    /*
     * PARSING
     */

    program = ((program = strrchr(argv[0], '/')) == (char *)0) ? argv[0] : program + 1;

    while ((opt = getopt(argc, argv, "C:D:E:K:L:P:R:b:d:f:ik:n:rt:x?")) >= 0) {

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

        case 'd':
            delay = optarg;
            break;

        case 'f':
            farend = optarg;
            role = CLIENT;
            break;

        case 'i':
            introduce = true;
            break;

        case 'k':
            keepalive = optarg;
            break;

        case 'n':
            nearend = optarg;
            role = SERVER;
            break;

        case 'r':
            selfsigned = false; /* Require certificates signed by a CA. */
            break;

        case 't':
            timeout = optarg;
            break;

        case 'x':
            daemonize = true;
            break;

        case '?':
            fprintf(stderr, "usage: %s [ -C CERTIFICATEFILE ] [ -D DHPARMSFILE ] [ -E EXPECTEDDOMAIN ] [ -K PRIVATEKEYFILE ] [ -L REVOCATIONFILE ] [ -P CERTIFICATESPATH ] [ -R ROOTFILE ] [ -b BYTES ] [ -d MILLISECONDS ] [ -f FARENDPOINT ] [ -i ] [ -k MILLISECONDS ] [ -n NEARENDPOINT ] [ -r ] [ -t MILLISECONDS ] [ -x ]\n", program);
            fprintf(stderr, "       -?                   prints this help menu and exits.\n");
            fprintf(stderr, "       -C CERTIFICATEFILE   is the .pem certificate.\n");
            fprintf(stderr, "       -D DHPARMSFILE       is the .pem Diffie-Hellman parameters file.\n");
            fprintf(stderr, "       -E EXPECTEDDOMAIN    is the expected fully-qualified domain name.\n");
            fprintf(stderr, "       -K PRIVATEKEYFILE    is the .pem private key file.\n");
            fprintf(stderr, "       -L REVOCATIONFILE    is the .pea revocation file.\n");
            fprintf(stderr, "       -P CERTIFICATESPATH  is the directory where CA certs can be found.\n");
            fprintf(stderr, "       -R ROOTFILE          is the .pem root certificate file.\n");
            fprintf(stderr, "       -b BYTES             is the allocated buffer size in bytes.\n");
            fprintf(stderr, "       -d MILLISECONDS      is the connection retry delay in milliseconds.\n");
            fprintf(stderr, "       -f FARENDPOINT       is the HOST:PORT far end point for client.\n");
            fprintf(stderr, "       -i                   introduce with an initial keepalive.\n");
            fprintf(stderr, "       -k MILLISECONDS      is the keepalive interval in milliseconds.\n");
            fprintf(stderr, "       -n NEARENDPOINT      is the :PORT or 0.0.0.0:PORT or [::]:PORT near end point for server.\n");
            fprintf(stderr, "       -r                   requires certificates signed by a CA.\n");
            fprintf(stderr, "       -t MILLISECONDS      sets the multiplexor timeout in milliseconds.\n");
            fprintf(stderr, "       -x                   daemonizes the process.\n");
            exit(1);
            break;

        }

    }

    switch (role) {
    case CLIENT:
        name = "codextoolclient";
        break;
    case SERVER:
        name = "codextoolserver";
        break;
    default:
        diminuto_assert(false);
        break;
    }

    if (daemonize) {
        DIMINUTO_LOG_NOTICE("%s: %s daemonize=%d\n", program, name, daemonize);
        rc = diminuto_daemon(name);
        diminuto_assert(rc == 0);
    }

    (void)snprintf(maskfile, sizeof(maskfile), "%s/%s-%d.msk", MASKPATH, program, getpid());
    if ((filetype = diminuto_fs_type(maskfile)) == DIMINUTO_FS_TYPE_FILE) {
        (void)diminuto_log_importmask(maskfile);
    }
    (void)diminuto_log_setmask();
    DIMINUTO_LOG_NOTICE("%s: %s file=\"%s\" type=%c mask=0x%x\n", program, name, maskfile, filetype, diminuto_log_mask);

    DIMINUTO_LOG_INFORMATION("%s: %s begin C=\"%s\" D=\"%s\" K=\"%s\" L=\"%s\" P=\"%s\" R=\"%s\" b=\"%s\" d=\"%s\" e=\"%s\" f=\"%s\" i=%d k=\"%s\" n=\"%s\" r=%d t=\"%s\" x=%d %c=%d\n",
        program,
        name,
        (pathcrt == (const char *)0) ? "" : pathcrt,
        (pathdhf == (const char *)0) ? "" : pathdhf,
        (pathkey == (const char *)0) ? "" : pathkey,
        (pathcrl == (const char *)0) ? "" : pathcrl,
        (pathcap == (const char *)0) ? "" : pathcap,
        (pathcaf == (const char *)0) ? "" : pathcaf,
        (bytes == (const char *)0) ? "" : bytes,
        (delay == (const char *)0) ? "" : delay,
        (expected == (const char *)0) ? "" : expected,
        (farend == (const char *)0) ? "" : farend,
        introduce,
        (keepalive == (const char *)0) ? "" : keepalive,
        (nearend == (const char *)0) ? "" : nearend,
        !selfsigned,
        (timeout == (const char *)0) ? "" : timeout,
        daemonize,
        role, !0);

    if (bytes != (const char *)0) {
        bufsize = strtoul(bytes, &endptr, 0);
        diminuto_assert((endptr != (const char *)0) && (*endptr == '\0') && (0 < bufsize) && (bufsize < diminuto_maximumof(codex_header_t)));
    }
    DIMINUTO_LOG_INFORMATION("%s: %s bufsize=%zubytes\n", program, name, bufsize);

    if (delay != (const char *)0) {
        delaymilliseconds = strtoul(delay, &endptr, 0);
        diminuto_assert((endptr != (const char *)0) && (*endptr == '\0') && (delaymilliseconds > 0));
    }
    delayticks = diminuto_frequency_units2ticks(delaymilliseconds, 1000 /* Hz */);
    DIMINUTO_LOG_INFORMATION("%s: %s delay=%lums=%lluticks\n", program, name, delaymilliseconds, (diminuto_llu_t)delayticks);

    if (keepalive != (const char *)0) {
        keepalivemilliseconds = strtol(keepalive, &endptr, 0);
        diminuto_assert((endptr != (const char *)0) && (*endptr == '\0'));
    }
    keepaliveticks = (keepalivemilliseconds >= 0) ? diminuto_frequency_units2ticks(keepalivemilliseconds, 1000 /* Hz */) : -1;
    DIMINUTO_LOG_INFORMATION("%s: %s keepalive=%ldms=%lldticks\n", program, name, keepalivemilliseconds, (diminuto_lld_t)keepaliveticks);

    if (timeout != (const char *)0) {
        timeoutmilliseconds = strtoul(timeout, &endptr, 0);
        diminuto_assert((endptr != (const char *)0) && (*endptr == '\0') && (timeoutmilliseconds > 0));
    }
    timeoutticks = diminuto_frequency_units2ticks(timeoutmilliseconds, 1000 /* Hz */);
    DIMINUTO_LOG_INFORMATION("%s: %s timeout=%lums=%lluticks\n", program, name, timeoutmilliseconds, (diminuto_llu_t)timeoutticks);

    DIMINUTO_LOG_INFORMATION("%s: %s selfsigned=%d\n", program, name, selfsigned);

    /*
     * CHECKING
     */

    if (farend != (const char *)0) {
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
    }

    if (nearend != (const char *)0) {
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
    }

    switch (role) {

    case CLIENT:
        biotype = farendtype;
        ssltype = farendtype;
        diminuto_assert(farendpoint.tcp != 0);
        break;

    case SERVER:
        biotype = nearendtype;
        ssltype = nearendtype;
        diminuto_assert(nearendpoint.tcp != 0);
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
         * the private API. This should be done prior to Codex
         * initialization.
         */
        extern int codex_set_self_signed_certificates(int);
        codex_set_self_signed_certificates(selfsigned);
    }

    rc = codex_initialize(pathdhf, pathcrl);
    diminuto_assert(rc == 0);

    inpfd = fileno(stdin);
    diminuto_assert(inpfd >= 0);
    rc = diminuto_mux_register_read(&mux, inpfd);
    diminuto_assert(rc >= 0);

    outfd = fileno(stdout);
    diminuto_assert(outfd >= 0);

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
        DIMINUTO_LOG_INFORMATION("%s: %s bio (-) far end %s\n", program, name, address2string(biotype, &address, port));
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
        DIMINUTO_LOG_INFORMATION("%s: %s bio (%d) near end %s\n", program, name, biofd, address2string(biotype, &address, port));
        rc = diminuto_mux_register_accept(&mux, biofd);
        diminuto_assert(rc >= 0);
        break;

    default:
        diminuto_assert(false);
        break;

    }

    /*
     * WORK LOOP
     */

    do {

        if (diminuto_hangup_check()) {
            DIMINUTO_LOG_NOTICE("%s: SIGHUP\n", program);
            if ((filetype = diminuto_fs_type(maskfile)) == DIMINUTO_FS_TYPE_FILE) {
                (void)diminuto_log_importmask(maskfile);
            }
            DIMINUTO_LOG_NOTICE("%s: %s file=\"%s\" type=%c mask=0x%x\n", program, name, maskfile, filetype, diminuto_log_mask);
            diminuto_yield();
        }

        if (diminuto_terminator_check()) {
            DIMINUTO_LOG_NOTICE("%s: %s SIGTERM\n", program, name);
            done = true;
        }

        if (!done) {

            /*
             * CONNECTING
             */

            switch (role) {

            case CLIENT:
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
                        DIMINUTO_LOG_INFORMATION("%s: %s ssl (%d) near end %s\n", program, name, sslfd, address2string(ssltype, &address, port));
                        rc = connection_farend(ssltype, sslfd, &address, &port);
                        diminuto_assert(rc >= 0);
                        DIMINUTO_LOG_INFORMATION("%s: %s ssl (%d) far end %s\n", program, name, sslfd, address2string(ssltype, &address, port));
                        rc = diminuto_mux_register_read(&mux, sslfd);
                        diminuto_assert(rc >= 0);
                    } else {
                        /*
                         * No server; try again later.
                         */
                        DIMINUTO_LOG_NOTICE("%s: %s ssl (%d) far end failed\n", program, name, sslfd);
                        diminuto_delay(delayticks, !0);
                        continue;
                    }
                }
                break;

            case SERVER:
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
            if ((fds < 0) && (errno == EINTR)) {
                continue;
            }
            DIMINUTO_LOG_DEBUG("%s: %s fds=%d\n", program, name, fds);

            /*
             * SERVER SSL
             */

            if (role != SERVER) {
                /* Do nothing. */
            } else if (fds <= 0) {
                /* Do nothing. */
            } else if (sslfd >= 0) {
                /* Do nothing. */
            } else if ((acceptfd = diminuto_mux_ready_accept(&mux)) < 0) {
                /* Do nothing. */
            } else if (acceptfd != biofd) {
                diminuto_assert(false);
            } else {
                fds -= 1;
                diminuto_assert(ssl == (codex_connection_t *)0);
                ssl = codex_server_connection_new(ctx, bio);
                diminuto_assert(ssl != (codex_connection_t *)0);
                diminuto_assert(codex_connection_is_server(ssl));
                diminuto_assert(sslfd < 0);
                sslfd = codex_connection_descriptor(ssl);
                diminuto_assert(sslfd >= 0);
                rc = connection_nearend(ssltype, sslfd, &address, &port);
                diminuto_assert(rc >= 0);
                DIMINUTO_LOG_INFORMATION("%s: %s ssl (%d) near end %s\n", program, name, sslfd, address2string(ssltype, &address, port));
                rc = connection_farend(ssltype, sslfd, &address, &port);
                diminuto_assert(rc >= 0);
                DIMINUTO_LOG_INFORMATION("%s: %s ssl (%d) far end %s\n", program, name, sslfd, address2string(ssltype, &address, port));
                rc = diminuto_mux_register_read(&mux, sslfd);
                diminuto_assert(rc >= 0);
                rc = diminuto_mux_unregister_accept(&mux, biofd);
                diminuto_assert(rc >= 0);
            }

            if (ssl == (codex_connection_t *)0) {
                /*
                 * No client, try again later.
                 */
                diminuto_delay(delayticks, !0);
                continue;
            }

            /*
             * PROCESSING
             */

            diminuto_assert(sslfd >= 0);

            status = readerwriter(role, introduce, fds, &mux, inpfd, ssl, outfd, bufsize, expected, keepaliveticks);

            switch (status) {
            case STDDONE:
            case ALLDONE:
                done = true;
                DIMINUTO_LOG_DEBUG("%s: %s done\n", program, name);
                break;
            default:
                /* Do nothing. */
                break;
            }

        }

        /*
         * RECOVERING
         */

        if (done) {
            /* Do nothing. */
        } else if (status != SSLDONE) {
            /* Do nothing. */
        } else if (ssl == (codex_connection_t *)0) {
            /* Do nothing. */
        } else {
            /*
             * May already be closed by virtue of far end closing,
             * so we ignore the value returned.
             */
            (void)codex_connection_close(ssl);
            ssl = codex_connection_free(ssl);
            diminuto_assert(ssl == (codex_connection_t *)0);
            if (sslfd >= 0) {
                (void)diminuto_mux_unregister_read(&mux, sslfd);
                (void)diminuto_mux_unregister_write(&mux, sslfd);
                sslfd = -1;
            }
            if (role == SERVER) {
                rc = diminuto_mux_register_accept(&mux, biofd);
                diminuto_assert(rc >= 0);
            }
        }

    } while (!done);

    /*
     * FINALIZATING
     */

    DIMINUTO_LOG_INFORMATION("%s: end\n", program);

    readerwriterfini();

    if (sslfd >= 0) {
        (void)diminuto_mux_unregister_read(&mux, sslfd);
        (void)diminuto_mux_unregister_write(&mux, sslfd);
        sslfd = -1;
    }

    diminuto_mux_fini(&mux);

    if (ssl != (codex_connection_t *)0) {
        (void)codex_connection_close(ssl);
        ssl = codex_connection_free(ssl);
        diminuto_assert(ssl == (codex_connection_t *)0);
    }

    if (biofd >= 0) {
        (void)diminuto_mux_unregister_accept(&mux, biofd);
        biofd = -1;
    }

    if (bio != (codex_rendezvous_t *)0) {
        bio = codex_server_rendezvous_free(bio);
        diminuto_assert(bio == (codex_rendezvous_t *)0);
    }

    if (ctx != (codex_context_t *)0) {
        ctx = codex_context_free(ctx);
        diminuto_assert(ctx == (codex_context_t *)0);
    }

    exit(0);
}
