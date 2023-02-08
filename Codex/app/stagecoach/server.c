/* vi: set ts=4 expandtab shiftwidth=4: */

/**
 * @file
 *
 * Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 * This is based on the code I wrote for the functionaltest-machine-server
 * and the functionaltest-machine-server functional test programs.
 */

#include "com/diag/codex/codex.h"
#include "com/diag/diminuto/diminuto_assert.h"
#include "com/diag/diminuto/diminuto_core.h"
#include "com/diag/diminuto/diminuto_ipc4.h"
#include "com/diag/diminuto/diminuto_ipc6.h"
#include "com/diag/diminuto/diminuto_log.h"
#include "com/diag/diminuto/diminuto_minmaxof.h"
#include "globals.h"
#include "protocols.h"
#include "server.h"

static bool initialized = false;
static codex_state_t state[DIRECTIONS] = { CODEX_STATE_START, CODEX_STATE_COMPLETE, };
static codex_header_t header[DIRECTIONS] = { 0, 0, };
static void * buffer[DIRECTIONS] = { (void *)0, (void *)0, };
static uint8_t * here[DIRECTIONS] = { (uint8_t *)0, (uint8_t *)0, };
static size_t length[DIRECTIONS] = { 0, 0, };
static bool first = true;

status_t server(int fds, diminuto_mux_t * muxp, protocol_t udptype, int udpfd, const address_t * serviceaddressp, port_t serviceport, codex_connection_t * ssl, size_t bufsize, const char * expected)
{
    int muxfd = -1;
    int sslfd = -1;
    ssize_t bytes = -1;
    status_t status = CONTINUE;
    address_t address = { 0, };
    port_t port = 0;

    if (!initialized) {
        diminuto_assert(bufsize > 0);
        buffer[READER] = malloc(bufsize);
        diminuto_assert(buffer[READER] != (void *)0);
        buffer[WRITER] = malloc(bufsize);
        diminuto_assert(buffer[WRITER] != (void *)0);
        initialized = true;
    }

    diminuto_assert(ssl != (codex_connection_t *)0);
    sslfd = codex_connection_descriptor(ssl);
    diminuto_assert(sslfd >= 0);

    do {

        muxfd = (fds > 0) ? diminuto_mux_ready_read(muxp) : -1;

        if ((muxfd >= 0) && (muxfd == udpfd)) {
            switch (state[WRITER]) {
            case CODEX_STATE_COMPLETE:
                bytes = datagram_receive(udptype, udpfd, buffer[WRITER], bufsize, &address, &port);
                if (bytes < 0) {
                    DIMINUTO_LOG_WARNING("%s: server writer udp (%d) [%zd] error\n", program, udpfd, bytes);
                    status = UDPRETRY;
                } else if (bytes == 0) {
                    DIMINUTO_LOG_NOTICE("%s: server writer udp (%d) [%zd] disconnect\n", program, udpfd, bytes);
                    status = UDPRETRY;
                } else if (bytes > diminuto_maximumof(codex_header_t)) {
                    DIMINUTO_LOG_ERROR("%s: server writer udp (%d) [%zd] overflow\n", program, udpfd, bytes);
                    status = UDPRETRY;
                } else {
                    DIMINUTO_LOG_DEBUG("%s: server writer udp (%d) [%zd] far end %s\n", program, udpfd, bytes, address2string(udptype, &address, port));
                    header[WRITER] = bytes;
                    if (first) {
                        state[WRITER] = CODEX_STATE_START;
                        first = false;
                    } else {
                        state[WRITER] = CODEX_STATE_RESTART;
                    }
                }
                break;
            case CODEX_STATE_START:
            case CODEX_STATE_RESTART:
            case CODEX_STATE_HEADER:
            case CODEX_STATE_PAYLOAD:
            case CODEX_STATE_SKIP:
                /* Do nothing. */
                break;
            case CODEX_STATE_FINAL:
                DIMINUTO_LOG_ERROR("%s: server writer ssl (%d) [%d] final\n", program, sslfd, header[WRITER]);
                status = SSLRETRY;
                break;
            case CODEX_STATE_IDLE:
                DIMINUTO_LOG_ERROR("%s: server writer ssl (%d) [%d] idle\n", program, sslfd, header[WRITER]);
                status = SSLRETRY;
                break;
            }
        }

        if (status != CONTINUE) {
            break;
        }

        switch (state[WRITER]) {
        case CODEX_STATE_START:
        case CODEX_STATE_RESTART:
            DIMINUTO_LOG_DEBUG("%s: server writer ssl (%d) [%d] start\n", program, sslfd, header[WRITER]);
            /* Fall through. */
        case CODEX_STATE_HEADER:
        case CODEX_STATE_PAYLOAD:
        case CODEX_STATE_SKIP:
            state[WRITER] = codex_machine_writer(state[WRITER], expected, ssl, &(header[WRITER]), buffer[WRITER], header[WRITER], &(here[WRITER]), &(length[WRITER]));
            switch (state[WRITER]) {
            case CODEX_STATE_FINAL:
                DIMINUTO_LOG_NOTICE("%s: server writer ssl (%d) [%d] final\n", program, sslfd, header[WRITER]);
                status = SSLRETRY;
                break;
            case CODEX_STATE_IDLE:
                DIMINUTO_LOG_ERROR("%s: server writer ssl (%d) [%d] idle\n", program, sslfd, header[WRITER]);
                status = SSLRETRY;
                break;
            case CODEX_STATE_COMPLETE:
                DIMINUTO_LOG_DEBUG("%s: server writer ssl (%d) [%d] complete\n", program, sslfd, header[WRITER]);
                break;
            case CODEX_STATE_START:
            case CODEX_STATE_RESTART:
            case CODEX_STATE_HEADER:
            case CODEX_STATE_PAYLOAD:
            case CODEX_STATE_SKIP:
                /* Do nothing. */
                break;
            }
            break;
        case CODEX_STATE_IDLE:
            DIMINUTO_LOG_ERROR("%s: server writer ssl (%d) [%d] idle\n", program, sslfd, header[WRITER]);
            status = SSLRETRY;
            break;
        case CODEX_STATE_COMPLETE:
            /* Do nothing. */
            break;
        case CODEX_STATE_FINAL:
            DIMINUTO_LOG_ERROR("%s: server writer ssl (%d) [%d] final\n", program, sslfd, header[WRITER]);
            status = SSLRETRY;
            break;
        }

        if (status != CONTINUE) {
            break;
        }

        while (((muxfd >= 0) && (muxfd == sslfd)) || codex_connection_is_ready(ssl)) {
            switch (state[READER]) {
            case CODEX_STATE_START:
            case CODEX_STATE_RESTART:
                DIMINUTO_LOG_DEBUG("%s: server reader ssl (%d) [%d] start\n", program, sslfd, header[READER]);
                /* Fall through. */
            case CODEX_STATE_HEADER:
            case CODEX_STATE_PAYLOAD:
            case CODEX_STATE_SKIP:
                state[READER] = codex_machine_reader(state[READER], expected, ssl, &(header[READER]), buffer[READER], bufsize, &(here[READER]), &(length[READER]));
                switch (state[READER]) {
                case CODEX_STATE_COMPLETE:
                    DIMINUTO_LOG_DEBUG("%s: server reader ssl (%d) [%d] complete\n", program, sslfd, header[READER]);
                    bytes = datagram_send(udptype, udpfd, buffer[READER], header[READER], serviceaddressp, serviceport);
                    if (bytes == header[READER]) {
                        DIMINUTO_LOG_DEBUG("%s: server reader udp (%d) [%zd] restart\n", program, udpfd, bytes);
                        state[READER] = CODEX_STATE_RESTART;
                    } else if (bytes == 0) {
                        DIMINUTO_LOG_NOTICE("%s: server reader udp (%d) [%zd] disconnect\n", program, udpfd, bytes);
                        status = UDPRETRY;
                    } else {
                        DIMINUTO_LOG_WARNING("%s: server reader udp (%d) [%zd] error\n", program, udpfd, bytes);
                        status = UDPRETRY;
                    }
                    break;
                case CODEX_STATE_FINAL:
                    DIMINUTO_LOG_NOTICE("%s: server reader ssl (%d) [%d] final\n", program, sslfd, header[WRITER]);
                    status = SSLRETRY;
                    break;
                case CODEX_STATE_IDLE:
                    DIMINUTO_LOG_ERROR("%s: server reader ssl (%d) [%d] idle\n", program, sslfd, header[WRITER]);
                    status = SSLRETRY;
                    break;
                case CODEX_STATE_START:
                case CODEX_STATE_RESTART:
                case CODEX_STATE_HEADER:
                case CODEX_STATE_PAYLOAD:
                case CODEX_STATE_SKIP:
                    /* Do nothing. */
                    break;
                }
                break;
            case CODEX_STATE_COMPLETE:
                DIMINUTO_LOG_ERROR("%s: server reader ssl (%d) [%d] complete\n", program, sslfd, header[WRITER]);
                status = SSLRETRY;
                break;
            case CODEX_STATE_IDLE:
                DIMINUTO_LOG_ERROR("%s: server reader ssl (%d) [%d] idle\n", program, sslfd, header[WRITER]);
                status = SSLRETRY;
                break;
            case CODEX_STATE_FINAL:
                DIMINUTO_LOG_NOTICE("%s: server reader ssl (%d) [%d] final\n", program, sslfd, header[WRITER]);
                status = SSLRETRY;
                break;
            }
            muxfd = -1;
            if (status != CONTINUE) {
                break;
            }
        }

        if (status != CONTINUE) {
            break;
        }

    } while (false);

    if (status != CONTINUE) {
        state[READER] = CODEX_STATE_START;
        state[WRITER] = CODEX_STATE_COMPLETE;
        first = true;
    }

    return status;
}
