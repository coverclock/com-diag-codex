/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2021 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 * This program terminates SSL stream connections from one or more
 * remote devices (typically a Digi Xbee 3 LTE-M radio module),
 * extracts NL-terminated JSON records from each stream, and emits
 * them as UDP datagrams to the specified port.
 * This program is based on the code in functionaltest-core-server.
 *
 * WORK IN PROGRESS
 */

#include "com/diag/diminuto/diminuto_assert.h"
#include "com/diag/diminuto/diminuto_core.h"
#include "com/diag/diminuto/diminuto_delay.h"
#include "com/diag/diminuto/diminuto_fd.h"
#include "com/diag/diminuto/diminuto_hangup.h"
#include "com/diag/diminuto/diminuto_ipc.h"
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

#define COM_DIAG_CODEX_OUT_CRT_PATH "out/host/crt"

static const char * program = "wheatstoneserver";
static const char * nearend = "*:wheatstone";
static const char * farend = "tesoro:tesoro";
static const char * expected = "wheatstone.prairiethorn.org";
static const char * pathcaf = COM_DIAG_CODEX_OUT_CRT_PATH "/" "root.pem";
static const char * pathcrt = COM_DIAG_CODEX_OUT_CRT_PATH "/" "wheatstoneserver.pem";
static const char * pathkey = COM_DIAG_CODEX_OUT_CRT_PATH "/" "wheatstoneserver.pem";
static const char * pathdhf = COM_DIAG_CODEX_OUT_CRT_PATH "/" "dh.pem";
static const char * pathcap = (const char *)0;
static size_t bufsize = 256;
static int selfsigned = -1;

typedef struct Client {
    diminuto_tree_t client_node;
    codex_connection_t * client_ssl;
    uint8_t * client_buffer;
    uint8_t * client_here;
    uint8_t * client_past;
    int client_fd;
} client_t;

static int client_compare(diminuto_tree_t * tAp, diminuto_tree_t * tBp)
{
    int rc = 0;
    client_t * cAp = (client_t *)0;
    client_t * cBp = (client_t *)0;
    int fdA = -1;
    int fdB = -1;

    cAp = (client_t *)diminuto_tree_data(tAp);
    cBp = (client_t *)diminuto_tree_data(tBp);

    fdA = codex_connection_descriptor(cAp->client_ssl);
    fdB = codex_connection_descriptor(cBp->client_ssl);

    if (fdA < fdB) {
        rc = -1;
    } else if (fdA > fdB) {
        rc = 1;
    } else {
        /* Do nothing. */
    }

    return rc;
}

static client_t * client_allocate(size_t bufsize)
{
    client_t * cp = (client_t *)0;
    diminuto_tree_t * tp = (diminuto_tree_t *)0;

    cp = (client_t *)malloc(sizeof(client_t));
    tp = diminuto_tree_datainit(&(cp->client_node), cp);
    diminuto_assert(tp != (diminuto_tree_t *)0);
    cp->client_ssl = (codex_connection_t *)0;
    cp->client_buffer = (uint8_t *)malloc(bufsize);
    diminuto_assert(cp->client_buffer != (uint8_t *)0);
    cp->client_here = (uint8_t *)0; /* NULL means unsynchronized. */
    cp->client_past = cp->client_buffer + bufsize;
    cp->client_fd = -1;

    return cp;
}

static client_t * client_free(client_t * cp, diminuto_mux_t * mp)
{
    int rc = -1;
    int fd = -1;
    codex_connection_t * sp = (codex_connection_t *)0;
    diminuto_tree_t * tp = (diminuto_tree_t *)0;

    diminuto_assert(cp != (client_t *)0);
    tp = diminuto_tree_remove(&(cp->client_node));
    diminuto_assert(tp == &(cp->client_node));
    if (cp->client_ssl == (codex_connection_t *)0) {
        /* Do nothing. */
    } else if (mp == (diminuto_mux_t *)0) {
        /* Do nothing. */
    } else {
        rc = diminuto_mux_unregister_read(mp, codex_connection_descriptor(cp->client_ssl));
        diminuto_assert(rc >= 0);
    }
    if (cp->client_ssl != (codex_connection_t *)0) {
        rc = codex_connection_close(cp->client_ssl);
        diminuto_assert(rc >= 0);
        sp = codex_connection_free(cp->client_ssl);
        diminuto_assert(sp == (codex_connection_t *)0);
        cp->client_ssl = (codex_connection_t *)0;;
    }
    if (cp->client_buffer != (uint8_t *)0) {
        free(cp->client_buffer);
        cp->client_buffer = (uint8_t *)0;
        cp->client_here = (uint8_t *)0;
    }
    free(cp);

    return (client_t *)0;
}

static ssize_t client_read(client_t * cp, size_t length)
{
    ssize_t bytes = -1;

    do {

        if (cp->client_here == (uint8_t *)0) {
            bytes = codex_connection_read(cp->client_ssl, cp->client_buffer, cp->client_past - cp->client_buffer);
            DIMINUTO_LOG_DEBUG("%s: READ connection=%p bytes=%d\n", program, cp->client_ssl, bytes);
            if (bytes <= 0) {
                break;
            }
            cp->client_here = cp->client_buffer;
        } else {
            bytes = codex_connection_read(cp->client_ssl, cp->client_here, 1);
            DIMINUTO_LOG_DEBUG("%s: READ connection=%p bytes=%d\n", program, cp->client_ssl, bytes);
            if (bytes > 0) {
            }
        }

    } while (false);

    return bytes;
}

int main(int argc, char ** argv)
{
    codex_context_t * ctx = (codex_context_t *)0;
    codex_rendezvous_t * bio = (codex_rendezvous_t *)0;
    client_t * this = (client_t *)0;
    client_t * that = (client_t *)0;
    diminuto_tree_t * root = DIMINUTO_TREE_EMPTY;
    diminuto_tree_t * node = DIMINUTO_TREE_NULL;
    diminuto_tree_t * next = DIMINUTO_TREE_NULL;
    diminuto_mux_t mux = { 0 };
    diminuto_ipc_endpoint_t endpoint = { 0, };
    ssize_t count = 0;
    int rc = -1;
    int fd = -1;
    int sock = -1;
    int comparison = 0;
    int rendezvous = -1;
    ssize_t bytes = -1;
    ssize_t reads = -1;
    char * endptr = (char *)0;
    int opt = '\0';
    extern char * optarg;

    /*
     * Configure.
     */

    (void)diminuto_core_enable();

    diminuto_log_setmask();

    program = ((program = strrchr(argv[0], '/')) == (char *)0) ? argv[0] : program + 1;

    while ((opt = getopt(argc, argv, "B:C:D:F:K:L:P:R:SVe:n:sv?")) >= 0) {

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

        case 'F':
            farend = optarg;
            break;

        case 'K':
            pathkey = optarg;
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

        case 'e':
            expected = (*optarg != '\0') ? optarg : (const char *)0;
            break;

        case 'n':
            nearend = optarg;
            break;

        case 's':
            selfsigned = 1;
            break;

        case '?':
            fprintf(stderr, "usage: %s [ -B BUFSIZE ] [ -C CERTIFICATEFILE ] [ -D DHPARMSFILE ] [ -F FAREND ] [ -K PRIVATEKEYFILE ] [ -P CERTIFICATESPATH ] [ -R ROOTFILE ] [ -e EXPECTED ] [ -n NEAREND ] [ -S | -s ]\n", program);
            return 1;
            break;

        }

    }

    DIMINUTO_LOG_NOTICE("%s: BEGIN B=%zu C=\"%s\" D=\"%s\" K=\"%s\" P=\"%s\" R=\"%s\" U=\"%s\" e=\"%s\" n=\"%s\" s=%d\n", program, bufsize, pathcrt, pathdhf, pathkey, (pathcap == (const char *)0) ? "" : pathcap, (pathcaf == (const char *)0) ? "" : pathcaf, farend, (expected == (const char *)0) ? "" : expected, nearend, selfsigned);

#if 0

    /*
     * Initialize.
     */

    rc = diminuto_terminator_install(0);
    diminuto_assert(rc >= 0);

    rc = diminuto_hangup_install(0);
    diminuto_assert(rc >= 0);

    diminuto_mux_init(&mux);

    if (selfsigned >= 0) {
        extern int codex_set_self_signed_certificates(int);
        codex_set_self_signed_certificates(!!selfsigned);
    }

    rc = codex_initialize((const char *)0, pathdhf, pathcrl);
    diminuto_assert(rc == 0);

    ctx = codex_server_context_new(pathcaf, pathcap, pathcrt, pathkey);
    diminuto_assert(ctx != (codex_context_t *)0);

    /*
     * Establish the listen (SSL) socket connections.
     */

    bio = codex_server_rendezvous_new(nearend);
    diminuto_assert(bio != (codex_rendezvous_t *)0);

    rendezvous = codex_rendezvous_descriptor(bio);
    diminuto_assert(rendezvous >= 0);

    DIMINUTO_LOG_DEBUG("%s: LISTEN nearend=\"%s\" rendezvous=%p fd=%d\n", program, nearend, bio, rendezvous);

    rc = diminuto_mux_register_accept(&mux, rendezvous);
    diminuto_assert(rc >= 0);

    /*
     * Establish the sink (UDP) socket connection.
     */

    rc = diminuto_ipc_endpoint(farend, &endpoint);
    if (rc < 0) {
        /* Do nothing. */
    } else if (endpoint.udp <= 0) {
        rc = -1;
        errno = EINVAL;
    } else if (!diminuto_ipc6_is_unspecified(&endpoint.ipv6)) {
        sock = rc = diminuto_ipc6_datagram_peer(0);
    } else if (!diminuto_ipc4_is_unspecified(&endpoint.ipv4)) {
        sock = rc = diminuto_ipc4_datagram_peer(0);
    } else {
        rc = -1;
        errno = EINVAL;
    }
    if (rc < 0) {
        diminuto_perror(farend);
    }
    diminuto_assert(rc >= 0);

    /*
     * Start work loop.
     */

    while (!diminuto_terminator_check()) {

        if (diminuto_hangup_check()) {
            DIMINUTO_LOG_INFORMATION("%s: SIGHUP\n", program);
            /* Unimplemented. */
        }

        /*
         * Wait for connection or read requests.
         */

        rc = diminuto_mux_wait(&mux, -1);
        if ((rc == 0) || ((rc < 0) && (errno == EINTR))) {
            diminuto_yield();
            continue;
        }
        diminuto_assert(rc > 0);

        /*
         * Accept connection requests.
         */

        while (true) {

            fd = diminuto_mux_ready_accept(&mux);
            if (fd < 0) {
                break;
            }
            diminuto_assert(fd == rendezvous);

            if (that == (client_t *)0) {
                that = client_allocate(bufsize);
            }

            that->client_ssl = codex_server_connection_new(ctx, bio);
            if (that->client_ssl == (codex_connection_t *)0) {
                continue;
            }

            that->client_fd = codex_connection_descriptor(ssl);
            diminuto_assert(that->client_fd >= 0);

            DIMINUTO_LOG_INFORMATION("%s: ACCEPT connection=%p fd=%d\n", program, that->client_ssl, that->client_fd);

            node = diminuto_tree_search(root, &(that->node), &client_compare, &comparison);
            if (node == (diminuto_tree_t *)0) {
                node = diminuto_tree_insert_root(&(that->node), &root);
            } else if (comparison < 0) {
                node = diminuto_tree_insert_right(&(that->node), node);
            } else if (comparison > 0) {
                node = diminuto_tree_insert_left(&(that->node), node);
            } else {
                diminuto_assert(comparison != 0);
            }
            that = (client_t *)0;

            rc = diminuto_mux_register_read(&mux, fd);
            diminuto_assert(rc >= 0);

        }

        /*
         * Process read requests.
         */

        while (true) {

            fd = diminuto_mux_ready_read(&mux);
            if (fd < 0) {
                break;
            }

            if (that == (client_t *)0) {
                that = client_allocate(bufsize);
            }

            that->client_fd = fd;
           
            node = diminuto_tree_search(root, &(that->node), &client_compare, &comparison);
            diminuto_assert(node != (diminuto_tree_t *)0);
            diminuto_assert(comparison == 0);
            this = (client_t *)diminuto_tree_data(node);

            if (this->client_here == (uint8_t *)0) {
                bytes = codex_connection_read(this->client_ssl, &(this->buffer[0]), 1);
                DIMINUTO_LOG_DEBUG("%s: SYNC connection=%p bytes=%d\n", program, ssl, bytes);
            } else {
            }

            if (bytes <= 0) {
                DIMINUTO_LOG_INFORMATION("%s: CLOSE connection=%p\n", program, ssl);
                this = client_free(this, &mux);
                diminuto_assert(this == (client_t * )0);
            }

        }

        diminuto_yield();

    }

    DIMINUTO_LOG_NOTICE("%s: END\n", program);

    diminuto_mux_fini(&mux);

    diminuto_assert(bio != (codex_rendezvous_t *)0);
    fd = codex_rendezvous_descriptor(bio);

    diminuto_assert(fd >= 0);
    diminuto_assert(fd == rendezvous);
    rc = diminuto_mux_unregister_accept(&mux, fd);
    diminuto_assert(rc >= 0);

    bio = codex_server_rendezvous_free(bio);
    diminuto_assert(bio == (codex_rendezvous_t *)0);

    node = diminuto_tree_first(&root);
    while (node != (diminuto_tree_t *)0) {
        next = diminuto_tree_next(node);
        this = (client_t *)diminuto_tree_data(node);
        diminuto_assert(this != (client_t *)0;
        this = client_free(this, &mux);
        diminuto_assert(this == (client_t *)0);
        node = next;
    }

    diminuto_assert(ctx != (codex_context_t *)0);
    ctx = codex_context_free(ctx);
    diminuto_assert(ctx == (codex_context_t *)0);

#endif

    exit(0);
}
