/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2018-2025 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 */

#include "com/diag/diminuto/diminuto_unittest.h"
#include "com/diag/diminuto/diminuto_log.h"
#include "com/diag/diminuto/diminuto_core.h"
#include "com/diag/diminuto/diminuto_terminator.h"
#include "com/diag/diminuto/diminuto_hangup.h"
#include "com/diag/diminuto/diminuto_fd.h"
#include "com/diag/diminuto/diminuto_mux.h"
#include "com/diag/diminuto/diminuto_delay.h"
#include "com/diag/diminuto/diminuto_ipc.h"
#include "com/diag/codex/codex.h"
#include "unittest-codex.h"
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

static const char * program = "unittest-core-server";
static const char * nearend = "49162";
static const char * expected = "client.prairiethorn.org";
static size_t bufsize = 256;
static const char * pathcaf = COM_DIAG_CODEX_OUT_CRT_PATH "/" "root.pem";
static const char * pathcap = (const char *)0;
static const char * pathcrl = (const char *)0;
static const char * pathcrt = COM_DIAG_CODEX_OUT_CRT_PATH "/" "server.pem";
static const char * pathkey = COM_DIAG_CODEX_OUT_CRT_PATH "/" "server.pem";
static const char * pathdhf = COM_DIAG_CODEX_OUT_CRT_PATH "/" "dh.pem";
static int selfsigned = -1;
static int opened = 0;
static int closed = 0;

int main(int argc, char ** argv)
{
    uint8_t * buffer = (uint8_t *)0;
    int rc = -1;
    codex_context_t * ctx = (codex_context_t *)0;
    codex_rendezvous_t * bio = (codex_rendezvous_t *)0;
    ssize_t count = 0;
    diminuto_fd_map_t * map = (diminuto_fd_map_t *)0;
    void ** here = (void **)0;
    diminuto_mux_t mux = { 0 };
    int fd = -1;
    int rendezvous = -1;
    codex_connection_t * ssl = (codex_connection_t *)0;
    ssize_t bytes = -1;
    ssize_t reads = -1;
    ssize_t writes = -1;
    uintptr_t temp = 0;
    bool tripwire = false;
    char * endptr = (char *)0;
    int opt = '\0';
    extern char * optarg;

    (void)diminuto_core_enable();

    diminuto_log_setmask();

    program = ((program = strrchr(argv[0], '/')) == (char *)0) ? argv[0] : program + 1;

    while ((opt = getopt(argc, argv, "B:C:D:K:L:P:R:SVe:n:sv?")) >= 0) {

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
            fprintf(stderr, "usage: %s [ -B BUFSIZE ] [ -C CERTIFICATEFILE ] [ -D DHPARMSFILE ] [ -K PRIVATEKEYFILE ] [ -L REVOCATIONFILE ] [ -P CERTIFICATESPATH ] [ -R ROOTFILE ] [ -e EXPECTED ] [ -n NEAREND ] [ -S | -s ]\n", program);
            return 1;
            break;

        }

    }

    count = diminuto_fd_maximum();
    ASSERT(count > 0);

    DIMINUTO_LOG_INFORMATION("%s: BEGIN B=%zu C=\"%s\" D=\"%s\" K=\"%s\" L=\"%s\" P=\"%s\" R=\"%s\" e=\"%s\" n=\"%s\" s=%d fdcount=%zd\n", program, bufsize, pathcrt, pathdhf, pathkey, (pathcrl == (const char *)0) ? "" : pathcrl, (pathcap == (const char *)0) ? "" : pathcap, (pathcaf == (const char *)0) ? "" : pathcaf, (expected == (const char *)0) ? "" : expected, nearend, selfsigned, count);

    buffer = (uint8_t *)malloc(bufsize);
    ASSERT(buffer != (uint8_t *)0);

    map = diminuto_fd_map_alloc(count);
    ASSERT(map != (diminuto_fd_map_t *)0);

    rc = diminuto_terminator_install(0);
    ASSERT(rc >= 0);

    rc = diminuto_hangup_install(0);
    ASSERT(rc >= 0);

    diminuto_mux_init(&mux);

    if (selfsigned >= 0) {
        extern int codex_set_self_signed_certificates(int);
        codex_set_self_signed_certificates(!!selfsigned);
    }

    rc = codex_initialize(pathdhf, pathcrl);
    ASSERT(rc == 0);

    ctx = codex_server_context_new(pathcaf, pathcap, pathcrt, pathkey);
    ASSERT(ctx != (codex_context_t *)0);

    bio = codex_server_rendezvous_new(nearend);
    ASSERT(bio != (codex_rendezvous_t *)0);
    opened += 1;

    rendezvous = codex_rendezvous_descriptor(bio);
    ASSERT(rendezvous >= 0);

    DIMINUTO_LOG_DEBUG("%s: RUN rendezvous=%p fd=%d\n", program, bio, rendezvous);

    rc = diminuto_mux_register_accept(&mux, rendezvous);
    ASSERT(rc >= 0);

    while (!diminuto_terminator_check()) {

        if (diminuto_hangup_check()) {
            DIMINUTO_LOG_INFORMATION("%s: SIGHUP\n", program);
            /* Unimplemented. */
        }

        rc = diminuto_mux_wait(&mux, -1);
        if ((rc == 0) || ((rc < 0) && (errno == EINTR))) {
            diminuto_yield();
            continue;
        }
        ASSERT(rc > 0);

        while (true) {

            fd = diminuto_mux_ready_accept(&mux);
            if (fd < 0) {
                break;
            }

            ASSERT(fd == rendezvous);

            ssl = codex_server_connection_new(ctx, bio);
            EXPECT(ssl != (codex_connection_t *)0);
            if (ssl == (codex_connection_t *)0) {
                continue;
            }
            EXPECT(codex_connection_is_server(ssl));
            opened += 1;

            codex_perror("Test codex_perror");
            codex_serror("Test codex_serror", ssl, 0);

            fd = codex_connection_descriptor(ssl);
            ASSERT(fd >= 0);

            DIMINUTO_LOG_INFORMATION("%s: START connection=%p fd=%d\n", program, ssl, fd);

            here = diminuto_fd_map_ref(map, fd);
            ASSERT(here != (void **)0);
            ASSERT(*here == (void *)0);
            /*
             * This is horribly horribly dangerous: we're keeping a one-bit
             * flag in the low order bit of the connection (SSL) address. This
             * only works because the first field in the SSL structure is word
             * aligned, not byte aligned. One minor change to the SSL structure
             * and this breaks. But doing this keeps us from having to have a
             * second file descriptor map.
             */
            temp = (uintptr_t)ssl;
            temp |= 0x1;
            *here = (void *)temp;

            rc = diminuto_mux_register_read(&mux, fd);
            ASSERT(rc >= 0);

        }

        while (true) {

            fd = diminuto_mux_ready_read(&mux);
            if (fd < 0) {
                break;
            }

            here = diminuto_fd_map_ref(map, fd);
            ASSERT(here != (void **)0);
            ASSERT(*here != (void *)0);
            temp = (uintptr_t)*here;
            tripwire = (temp & 0x1) != 0;
            if (tripwire) {
                temp &= ~(uintptr_t)0x1;
                *here = (void *)temp;
            }
            ssl = (codex_connection_t *)temp;

            do {

                bytes = codex_connection_read(ssl, buffer, bufsize);
                DIMINUTO_LOG_DEBUG("%s: READ connection=%p bytes=%zd\n", program, ssl, bytes);

                if (bytes > 0) {

                    if (tripwire) {
                        rc = codex_connection_verify(ssl, expected);
                        if (!codex_connection_verified(rc)) {
                            bytes = 0;
                        }
                    }

                    for (reads = bytes, writes = 0; (writes < reads) && (bytes > 0); writes += bytes) {
                        bytes = codex_connection_write(ssl, buffer + writes, reads - writes);
                        DIMINUTO_LOG_DEBUG("%s: WRITE connection=%p bytes=%zd\n", program, ssl, bytes);
                    }

                }

                if (bytes <= 0) {

                    DIMINUTO_LOG_INFORMATION("%s: FINISH connection=%p\n", program, ssl);

                    rc = diminuto_mux_unregister_read(&mux, fd);
                    EXPECT(rc >= 0);

                    rc = codex_connection_close(ssl);
                    ADVISE(rc >= 0);
                    closed += 1;

                    ssl = codex_connection_free(ssl);
                    EXPECT(ssl == (codex_connection_t *)0);

                    *here = (void *)0;

                }

            } while ((ssl != (codex_connection_t *)0) && codex_connection_is_ready(ssl));

        }

        diminuto_yield();

    }

    DIMINUTO_LOG_INFORMATION("%s: END\n", program);

    diminuto_mux_fini(&mux);

    fd = codex_rendezvous_descriptor(bio);
    ASSERT(fd >= 0);
    ASSERT(fd == rendezvous);

    rc = diminuto_mux_unregister_accept(&mux, fd);
    EXPECT(rc >= 0);

    bio = codex_server_rendezvous_free(bio);
    ASSERT(bio == (codex_rendezvous_t *)0);
    closed += 1;

    for (fd = 0; fd < count; ++fd) {

        here = diminuto_fd_map_ref(map, fd);
        ASSERT(here != (void **)0);
        if (*here == (void *)0) { continue; }
        temp = (uintptr_t)*here;
        temp &= ~(uintptr_t)0x1;
        ssl = (codex_connection_t *)temp;

        rc = codex_connection_close(ssl);
        EXPECT(rc >= 0);
        closed += 1;

        ssl = codex_connection_free(ssl);
        EXPECT(ssl == (codex_connection_t *)0);

        *here = (void *)0;

    }

    free(map);

    ctx = codex_context_free(ctx);
    EXPECT(ctx == (codex_context_t *)0);

    free(buffer);

    DIMINUTO_LOG_INFORMATION("%s: DONE opened=%d closed=%d\n", program, opened, closed);
    EXPECT(opened == closed);

    EXIT();
}
