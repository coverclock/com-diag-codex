/* vi: set ts=4 expandtab shiftwidth=4: */

/**
 * @file
 *
 * Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 */

#include "com/diag/codex/codex.h"
#include "com/diag/diminuto/diminuto_assert.h"
#include "com/diag/diminuto/diminuto_core.h"
#include "com/diag/diminuto/diminuto_ipc.h"
#include "com/diag/diminuto/diminuto_ipc4.h"
#include "com/diag/diminuto/diminuto_ipc6.h"
#include "com/diag/diminuto/diminuto_log.h"
#include "com/diag/diminuto/diminuto_minmaxof.h"
#include "client.h"
#include "globals.h"
#include "protocols.h"

static bool initialized = false;
static codex_state_t state[DIRECTIONS] = { CODEX_STATE_START, CODEX_STATE_IDLE, };
static codex_header_t header[DIRECTIONS] = { 0, 0, };
static void * buffer[DIRECTIONS] = { (void *)0, (void *)0, };
static uint8_t * here[DIRECTIONS] = { (uint8_t *)0, (uint8_t *)0, };
static size_t length[DIRECTIONS] = { 0, 0, };
static bool first = true;
static address_t address = { 0, };
static diminuto_port_t port = 0;

status_t client(int fds, diminuto_mux_t * muxp, protocol_t udptype, int udpfd, codex_connection_t * ssl, size_t bufsize, const char * expected)
{
    status_t status = CONTINUE;
    int readfd = -1;
    int writefd = -1;
    int sslfd = -1;
    ssize_t bytes = -1;
    int rc = 0;

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

    while (fds > 0) {

        readfd = diminuto_mux_ready_read(muxp);
        writefd = diminuto_mux_ready_write(muxp);

        if (readfd == udpfd) {
            switch (state[WRITER]) {
            case CODEX_STATE_IDLE:
                bytes = datagram_receive(udptype, udpfd, buffer[WRITER], bufsize, &address, &port);
                if (bytes < 0) {
                    DIMINUTO_LOG_WARNING("%s: client writer udp (%d) [%zd] error\n", program, udpfd, bytes);
                    status = UDPDONE;
                } else if (bytes == 0) {
                    DIMINUTO_LOG_NOTICE("%s: client writer udp (%d) [%zd] disconnect\n", program, udpfd, bytes);
                    status = UDPDONE;
                } else if (bytes > diminuto_maximumof(codex_header_t)) {
                    DIMINUTO_LOG_ERROR("%s: client writer udp (%d) [%zd] overflow\n", program, udpfd, bytes);
                    status = UDPDONE;
                } else {
                    DIMINUTO_LOG_DEBUG("%s: client writer udp (%d) [%zd] far end %s\n", program, udpfd, bytes, address2string(udptype, &address, port));
                    header[WRITER] = bytes;
                    rc = diminuto_mux_register_write(muxp, sslfd);
                    diminuto_assert(rc >= 0);
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
                DIMINUTO_LOG_ERROR("%s: client writer ssl (%d) [%d] final\n", program, sslfd, header[WRITER]);
                status = SSLDONE;
                break;
            case CODEX_STATE_COMPLETE:
                DIMINUTO_LOG_ERROR("%s: client writer ssl (%d) [%d] complete\n", program, sslfd, header[WRITER]);
                status = SSLDONE;
                break;
            }
            readfd = -1;
            fds -= 1;
        }

        if (status != CONTINUE) {
            break;
        } else if (fds == 0) {
            break;
        } else {
            /* Do nothing. */
        }

        if (writefd == sslfd) {
            switch (state[WRITER]) {
            case CODEX_STATE_START:
            case CODEX_STATE_RESTART:
                DIMINUTO_LOG_DEBUG("%s: client writer ssl (%d) [%d] start\n", program, sslfd, header[WRITER]);
                /* Fall through. */
            case CODEX_STATE_HEADER:
            case CODEX_STATE_PAYLOAD:
            case CODEX_STATE_SKIP:
                state[WRITER] = codex_machine_writer(state[WRITER], expected, ssl, &(header[WRITER]), buffer[WRITER], header[WRITER], &(here[WRITER]), &(length[WRITER]));
                switch (state[WRITER]) {
                case CODEX_STATE_FINAL:
                    DIMINUTO_LOG_NOTICE("%s: client writer ssl (%d) [%d] final\n", program, sslfd, header[WRITER]);
                    status = SSLDONE;
                    break;
                case CODEX_STATE_IDLE:
                    DIMINUTO_LOG_ERROR("%s: client writer ssl (%d) [%d] idle\n", program, sslfd, header[WRITER]);
                    status = SSLDONE;
                    break;
                case CODEX_STATE_COMPLETE:
                    DIMINUTO_LOG_DEBUG("%s: client writer ssl (%d) [%d] complete\n", program, sslfd, header[WRITER]);
                    rc = diminuto_mux_unregister_write(muxp, sslfd);
                    diminuto_assert(rc >= 0);
                    state[WRITER] = CODEX_STATE_IDLE;
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
                /* Do nothing. */
                break;
            case CODEX_STATE_COMPLETE:
                DIMINUTO_LOG_ERROR("%s: client writer ssl (%d) [%d] complete\n", program, sslfd, header[WRITER]);
                status = SSLDONE;
                break;
            case CODEX_STATE_FINAL:
                DIMINUTO_LOG_ERROR("%s: client writer ssl (%d) [%d] final\n", program, sslfd, header[WRITER]);
                status = SSLDONE;
                break;
            }
            writefd = -1;
            fds -= 1;
        }

        if (status != CONTINUE) {
            break;
        } else if (fds == 0) {
            break;
        } else {
            /* Do nothing. */
        }

        while (readfd == sslfd) {
            switch (state[READER]) {
            case CODEX_STATE_START:
            case CODEX_STATE_RESTART:
                DIMINUTO_LOG_DEBUG("%s: client reader ssl (%d) [%d] start\n", program, sslfd, header[READER]);
                /* Fall through. */
            case CODEX_STATE_HEADER:
            case CODEX_STATE_PAYLOAD:
            case CODEX_STATE_SKIP:
                state[READER] = codex_machine_reader(state[READER], expected, ssl, &(header[READER]), buffer[READER], bufsize, &(here[READER]), &(length[READER]));
                switch (state[READER]) {
                case CODEX_STATE_COMPLETE:
                    DIMINUTO_LOG_DEBUG("%s: client reader ssl (%d) [%d] complete\n", program, sslfd, header[READER]);
                    if (port > 0) {
                        bytes = datagram_send(udptype, udpfd, buffer[READER], header[READER], &address, port);
                        if (bytes == header[READER]) {
                            DIMINUTO_LOG_DEBUG("%s: client reader udp (%d) [%zd] restart\n", program, udpfd, bytes);
                            state[READER] = CODEX_STATE_RESTART;
                        } else if (bytes == 0) {
                            DIMINUTO_LOG_NOTICE("%s: client reader udp (%d) [%zd] disconnect\n", program, udpfd, bytes);
                            status = UDPDONE;
                        } else {
                            DIMINUTO_LOG_WARNING("%s: client reader udp (%d) [%zd] error\n", program, udpfd, bytes);
                            status = UDPDONE;
                        }
                    } else {
                        DIMINUTO_LOG_INFORMATION("%s: client reader ssl (%d) [%d] orphan\n", program, sslfd, header[WRITER]);
                        state[READER] = CODEX_STATE_RESTART;
                    }
                    break;
                case CODEX_STATE_FINAL:
                    DIMINUTO_LOG_NOTICE("%s: client reader ssl (%d) [%d] final\n", program, sslfd, header[WRITER]);
                    status = SSLDONE;
                    break;
                case CODEX_STATE_IDLE:
                    DIMINUTO_LOG_ERROR("%s: client reader ssl (%d) [%d] idle\n", program, sslfd, header[WRITER]);
                    status = SSLDONE;
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
                DIMINUTO_LOG_ERROR("%s: client reader ssl (%d) [%d] complete\n", program, sslfd, header[WRITER]);
                status = SSLDONE;
                break;
            case CODEX_STATE_IDLE:
                DIMINUTO_LOG_ERROR("%s: client reader ssl (%d) [%d] idle\n", program, sslfd, header[WRITER]);
                status = SSLDONE;
                break;
            case CODEX_STATE_FINAL:
                DIMINUTO_LOG_ERROR("%s: client reader ssl (%d) [%d] final\n", program, sslfd, header[WRITER]);
                status = SSLDONE;
                break;
            }
            if (status != CONTINUE) {
                break;
            }
            /*
             * Consume all the data in the SSL pipeline.
             */
            if (!codex_connection_is_ready(ssl)) {
                readfd = -1;
                fds -= 1;
            }
        }

        if (status != CONTINUE) {
            break;
        } else if (fds == 0) {
            break;
        } else {
            /* Do nothing. */
        }

    }

    if (status != CONTINUE) {
        (void)diminuto_mux_unregister_write(muxp, sslfd);
        state[READER] = CODEX_STATE_START;
        state[WRITER] = CODEX_STATE_IDLE;
        first = true;
    }

    return status;
}
