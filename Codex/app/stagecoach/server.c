/* vi: set ts=4 expandtab shiftwidth=4: */

/**
 * @file
 *
 * Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 * This is based on the code I wrote for the functionaltest-machine-server
 * and the functionaltest-machine-client functional test programs.
 */

#include "com/diag/codex/codex.h"
#include "com/diag/diminuto/diminuto_assert.h"
#include "com/diag/diminuto/diminuto_core.h"
#include "com/diag/diminuto/diminuto_ipc4.h"
#include "com/diag/diminuto/diminuto_ipc6.h"
#include "com/diag/diminuto/diminuto_log.h"
#include "globals.h"
#include "server.h"

int server(diminuto_mux_t * muxp, protocol_t biotype, int biofd, protocol_t udptype, int udpfd, codex_context_t * ctx, codex_connection_t * ssl)
{
    int muxfd = -1;
    int reqfd = -1;
    codex_connection_t * req = (codex_connection_t *)0;

    while (true) {

        muxfd = diminuto_mux_ready_accept(muxp);
        if (muxfd < 0) {
            break;
        }
        diminuto_assert(muxfd == biofd);

        req = codex_server_connection_new(ctx, bio);
        diminuto_expect(req != (codex_connection_t *)0);
        if (req == (codex_connection_t *)0) {
            diminuto_yield();
            continue;
        }
        diminuto_expect(codex_connection_is_server(req));

        reqfd = codex_connection_descriptor(req);
        diminuto_assert(reqfd >= 0);

        switch (biotype) {
        case IPV4:
            rc = diminuto_ipc4_farend(reqfd, &ipv4address, &port);
            diminuto_assert(rc >= 0);
            DIMINUTO_LOG_NOTICE("%s: %s req [%d] far end %s:%d\n", program, name, reqfd, diminuto_ipc4_address2string(ipv4address, ipv4string, sizeof(ipv4string)), port);
            break;
        case IPV6:
            rc = diminuto_ipc6_farend(reqfd, &ipv6address, &port);
            diminuto_assert(rc >= 0);
            DIMINUTO_LOG_NOTICE("%s: %s req [%d] far end [%s]:%d\n", program, name, reqfd, diminuto_ipc6_address2string(ipv6address, ipv6string, sizeof(ipv6string)), port);
            break;
        default:
            diminuto_core_fatal();
            break;
        }

        if (expected != (const char *)0) {
            rc = codex_connection_verify(req, expected);
            if (!codex_connection_verified(rc)) {
                DIMINUTO_LOG_WARNING("%s: %s req [%d] failed 0x%x\n", program, name, reqfd, rc);
                rc = codex_connection_close(req);
                diminuto_assert(rc >= 0);
                req = codex_connection_free(req);
                diminuto_assert(req == (codex_connection_t *)0);
                req = (codex_connection_t *)0;
                rc = diminuto_ipc_close(reqfd);
                diminuto_expect(rc < 0);
                reqfd = -1;
            }
        }

        if (ssl != (codex_connection_t *)0) {
            rc = codex_connection_close(ssl);
            diminuto_assert(rc >= 0);
            ssl = codex_connection_free(ssl);
            diminuto_assert(ssl == (codex_connection_t *)0);
            rc = diminuto_mux_unregister_read(muxp, sslfd);
            diminuto_expect(rc >= 0);
            rc = diminuto_mux_unregister_write(muxp, sslfd);
            diminuto_expect(rc >= 0);
            rc = diminuto_ipc_close(sslfd);
            diminuto_expect(rc < 0);
            sslfd = -1;
            ssltype = UNKNOWN;
        }

        ssl = req;
        diminuto_assert(ssl != (codex_connection_t *)0);
        req = (codex_connection_t *)0;
        sslfd = codex_connection_descriptor(ssl);
        diminuto_assert(sslfd >= 0);
        ssltype = biotype;
        rc = diminuto_mux_register_read(muxp, sslfd);
        diminuto_assert(rc >= 0);
        rc = diminuto_mux_register_write(muxp, sslfd);
        diminuto_assert(rc >= 0);

        DIMINUTO_LOG_NOTICE("%s: %s ssl [%d] far end\n", program, name, reqfd);

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

                state = codex_machine_reader(client->source.state, expected, client->ssl, &(client->source.header), client->source.buffer, client->size, &(client->source.here), &(client->source.length));

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

            state = codex_machine_writer(client->sink.state, expected, client->ssl, &(client->sink.header), client->sink.buffer, client->sink.header, &(client->sink.here), &(client->sink.length));

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

    return -1;
}
