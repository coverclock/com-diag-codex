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
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct Stream {
    codex_state_t state;
    codex_header_t header;
    void * buffer;
    uint8_t * here;
    size_t length;
} stream_t;

typedef struct Client {
    codex_connection_t * ssl;
    size_t size;
    codex_indication_t indication;
    stream_t source;
    stream_t sink;
    bool checked;
} client_t;

static const char * program = "functionaltest-machine-server";
static const char * nearend = "49182";
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

static diminuto_mux_t mux = { 0 };
static diminuto_fd_map_t * map = (diminuto_fd_map_t *)0;
static codex_context_t * ctx = (codex_context_t *)0;
static codex_rendezvous_t * bio = (codex_rendezvous_t *)0;
static int rendezvous = -1;

static client_t * create(void)
{
    client_t * client = (client_t *)0;
    codex_connection_t * ssl = (codex_connection_t *)0;
    int fd = -1;
    int rc = -1;
    void ** here = (void **)0;

    do {

        ssl = codex_server_connection_new(ctx, bio);
        EXPECT(ssl != (codex_connection_t *)0);
        if (ssl == (codex_connection_t *)0) {
            break;
        }
        opened += 1;

        client = (client_t *)malloc(sizeof(client_t));
        ASSERT(client != (client_t *)0);
        memset(client, 0, sizeof(client_t));

        client->ssl = ssl;
        EXPECT(codex_connection_is_server(client->ssl));
        client->size = bufsize;

        client->indication = CODEX_INDICATION_NONE;

        client->source.state = CODEX_STATE_START;
        client->source.buffer = malloc(bufsize);
        ASSERT(client->source.buffer != (void *)0);

        client->sink.state = CODEX_STATE_IDLE;
        client->sink.buffer = malloc(bufsize);
        ASSERT(client->sink.buffer != (void *)0);

        client->checked = false;

        fd = codex_connection_descriptor(client->ssl);
        ASSERT(fd >= 0);

        rc = diminuto_mux_register_read(&mux, fd);
        ASSERT(rc >= 0);

        rc = diminuto_mux_register_write(&mux, fd);
        ASSERT(rc >= 0);

        here = diminuto_fd_map_ref(map, fd);
        ASSERT(here != (void **)0);
        ASSERT(*here == (void *)0);
        *here = (void *)client;

    } while (0);

    return client;
}

static client_t * destroy(client_t * client)
{
    int fd = -1;
    int rc = -1;
    void ** here = (void **)0;

    fd = codex_connection_descriptor(client->ssl);
    ASSERT(fd >= 0);

    here = diminuto_fd_map_ref(map, fd);
    ASSERT(here != (void **)0);
    ASSERT(*here != (void *)0);
    ASSERT(client == (client_t *)*here);
    *here = (void *)0;

    rc = diminuto_mux_unregister_read(&mux, fd);
    ASSERT(rc >= 0);

    rc = diminuto_mux_unregister_write(&mux, fd);
    ASSERT(rc >= 0);

    free(client->source.buffer);
    free(client->sink.buffer);

    if (client->source.state == CODEX_STATE_FINAL) {
        /* Do nothing. */
    } else if (client->sink.state == CODEX_STATE_FINAL) {
        /* Do nothing. */
    } else {
        rc = codex_connection_close(client->ssl);
        ASSERT(rc >= 0);
    }

    client->ssl = codex_connection_free(client->ssl);
    ASSERT(client->ssl == (codex_connection_t *)0);
    closed += 1;

    free(client);

    client = (client_t *)0;

    return client;
}

static void swap(client_t * client)
{
    void * temp = (void *)0;

    temp = client->sink.buffer;
    client->sink.buffer = client->source.buffer;
    client->sink.header = client->source.header;
    client->source.buffer = temp;

    client->source.state = CODEX_STATE_RESTART;
    client->sink.state = CODEX_STATE_RESTART;
}

static bool indicate(client_t * client)
{
    void * temp = (void *)0;

    if (client->indication == CODEX_INDICATION_NEAREND) {
        codex_state_t state = CODEX_STATE_RESTART;
        codex_header_t header = 0;
        uint8_t * here = (uint8_t *)0;
        size_t length = 0;
        bool checked = false;

        DIMINUTO_LOG_INFORMATION("%s: NEAREND client=%p\n", program, client);

        do {
            codex_serror_t serror = CODEX_SERROR_NONE;

            state = codex_machine_writer_generic(state, (char *)0, client->ssl, &header, (void *)0, CODEX_INDICATION_FAREND, &here, &length, &checked, &serror, (int *)0);

            if (serror == CODEX_SERROR_READ) {
                DIMINUTO_LOG_NOTICE("%s: WANT READ\n", program);
            }

        } while ((state != CODEX_STATE_FINAL) && (state != CODEX_STATE_COMPLETE));

        if (state == CODEX_STATE_FINAL) {
            return false;
        }

        temp = client->sink.buffer;
        client->sink.buffer = client->source.buffer;
        client->sink.header = client->source.header;
        client->source.buffer = temp;

        client->source.state = CODEX_STATE_RESTART;
        client->sink.state = CODEX_STATE_START;

    } else {

        DIMINUTO_LOG_INFORMATION("%s: FAREND client=%p\n", program, client);

        client->source.state = CODEX_STATE_START;
        client->sink.state = CODEX_STATE_IDLE; /* (No change.) */

    }

    client->indication = CODEX_INDICATION_NONE;

    return true;
}

int main(int argc, char ** argv)
{
    int rc = -1;
    ssize_t count = 0;
    int fd = -1;
    char * endptr = (char *)0;
    client_t * client = 0;
    codex_state_t state = CODEX_STATE_IDLE;
    void ** here = (void **)0;
    int opt = '\0';
    extern char * optarg;

    (void)diminuto_core_enable();

    diminuto_log_setmask();

    program = ((program = strrchr(argv[0], '/')) == (char *)0) ? argv[0] : program + 1;

    while ((opt = getopt(argc, argv, "B:C:D:K:L:P:R:Se:n:s?")) >= 0) {

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

    rc = diminuto_mux_register_accept(&mux, rendezvous);
    ASSERT(rc >= 0);

    while (!diminuto_terminator_check()) {

        if (diminuto_hangup_check()) {
            DIMINUTO_LOG_INFORMATION("%s: SIGHUP\n", program);
            for (fd = 0; fd < count; ++fd) {
                here = diminuto_fd_map_ref(map, fd);
                ASSERT(here != (void **)0);
                if (*here != (void *)0) {
                    client = (client_t *)*here;
                    client->indication = CODEX_INDICATION_NEAREND;
                }
            }
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

            client = create();
            DIMINUTO_LOG_INFORMATION("%s: START client=%p\n", program, client);

        }

        while (true) {

            fd = diminuto_mux_ready_read(&mux);
            if (fd < 0) {
                break;
            }

            here = diminuto_fd_map_ref(map, fd);
            ASSERT(here != (void **)0);
            ASSERT(*here != (void *)0);
            client = (client_t *)*here;

            if (client->source.state == CODEX_STATE_IDLE) {
                continue;
            }

            do {
                codex_serror_t serror = CODEX_SERROR_NONE;

                state = codex_machine_reader_generic(client->source.state, expected, client->ssl, &(client->source.header), client->source.buffer, client->size, &(client->source.here), &(client->source.length), &(client->checked), &serror, (int *)0);

                if (serror == CODEX_SERROR_WRITE) {
                    DIMINUTO_LOG_NOTICE("%s: WANT WRITE\n", program);
                }

                if (state == CODEX_STATE_FINAL) {

                    DIMINUTO_LOG_INFORMATION("%s: FINAL client=%p fd=%d\n", program, client, fd);
                    client = destroy(client);
                    break;

                }

                if (state == client->source.state) {
                    /* Do nothing. */
                } else if (state != CODEX_STATE_COMPLETE) {
                    /* Do nothing. */
                } else if (client->source.header == CODEX_INDICATION_FAREND) {

                    DIMINUTO_LOG_INFORMATION("%s: INDICATION client=%p indication=%d\n", program, client, client->source.header);
                    client->indication = CODEX_INDICATION_FAREND;
                    state = CODEX_STATE_IDLE;

                } else {

                    DIMINUTO_LOG_DEBUG("%s: READ client=%p bytes=%d\n", program, client, client->source.header);
                    state = CODEX_STATE_IDLE;

                }

                client->source.state = state;

                if (client->sink.state != CODEX_STATE_IDLE) {
                    break;
                } else if (client->source.state != CODEX_STATE_IDLE) {
                    /* Do nothing. */
                } else if (client->indication == CODEX_INDICATION_NONE) {

                    swap(client);

                } else {

                    DIMINUTO_LOG_INFORMATION("%s: INDICATING client=%p\n", program, client);
                    if (!indicate(client)) {
                        DIMINUTO_LOG_INFORMATION("%s: FINAL client=%p fd=%d\n", program, client, fd);
                        client = destroy(client);
                        break;
                    }

                }

            } while ((client != (client_t *)0) && codex_connection_is_ready(client->ssl));

        }

        while (true) {
            codex_serror_t serror = CODEX_SERROR_NONE;

            fd = diminuto_mux_ready_write(&mux);
            if (fd < 0) {
                break;
            }

            here = diminuto_fd_map_ref(map, fd);
            ASSERT(here != (void **)0);
            ASSERT(*here != (void *)0);
            client = (client_t *)*here;

            if (client->sink.state == CODEX_STATE_IDLE) {
                continue;
            }

            state = codex_machine_writer_generic(client->sink.state, expected, client->ssl, &(client->sink.header), client->sink.buffer, client->sink.header, &(client->sink.here), &(client->sink.length), &(client->checked), &serror, (int *)0);

            if (serror == CODEX_SERROR_READ) {
                DIMINUTO_LOG_NOTICE("%s: WANT READ\n", program);
            }

            if (state == CODEX_STATE_FINAL) {

                DIMINUTO_LOG_INFORMATION("%s: FINAL client=%p fd=%d\n", program, client, fd);
                client = destroy(client);
                continue;

            }

            if (state == client->sink.state) {
                /* Do nothing. */
            } else if (state != CODEX_STATE_COMPLETE) {
                /* Do nothing. */
            } else {

                DIMINUTO_LOG_DEBUG("%s: WRITE client=%p bytes=%d\n", program, client, client->sink.header);
                state = CODEX_STATE_IDLE;

            }

            client->sink.state = state;

            if (client->sink.state != CODEX_STATE_IDLE) {
                /* Do nothing. */
            } else if (client->source.state != CODEX_STATE_IDLE) {
                /* Do nothing. */
            } else if (!client->indication) {

                swap(client);

            } else {

                DIMINUTO_LOG_INFORMATION("%s: INDICATING client=%p\n", program, client);
                if (!indicate(client)) {
                    DIMINUTO_LOG_INFORMATION("%s: FINAL client=%p fd=%d\n", program, client, fd);
                    client = destroy(client);
                }

            }

        }

        diminuto_yield();

    }

    DIMINUTO_LOG_INFORMATION("%s: END\n", program);

    diminuto_mux_fini(&mux);

    fd = codex_rendezvous_descriptor(bio);
    ASSERT(fd >= 0);
    ASSERT(fd == rendezvous);

    rc = diminuto_mux_unregister_accept(&mux, fd);
    ASSERT(rc >= 0);

    bio = codex_server_rendezvous_free(bio);
    ASSERT(bio == (codex_rendezvous_t *)0);
    closed += 1;

    for (fd = 0; fd < count; ++fd) {

        here = diminuto_fd_map_ref(map, fd);
        ASSERT(here != (void **)0);
        if (*here == (void *)0) { continue; }
        client = (client_t *)*here;

        client = destroy(client);

    }

    diminuto_mux_fini(&mux);

    free(map);

    ctx = codex_context_free(ctx);
    EXPECT(ctx == (codex_context_t *)0);

    DIMINUTO_LOG_INFORMATION("%s: DONE opened=%d closed=%d\n", program, opened, closed);
    EXPECT(opened == closed);

    EXIT();
}
