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
static codex_state_t restate = CODEX_STATE_START;
static codex_header_t header[DIRECTIONS] = { 0, 0, };
static void * buffer[DIRECTIONS] = { (void *)0, (void *)0, };
static uint8_t * here[DIRECTIONS] = { (uint8_t *)0, (uint8_t *)0, };
static size_t length[DIRECTIONS] = { 0, 0, };

status_t readerwriter(role_t role, int fds, diminuto_mux_t * muxp, protocol_t udptype, int udpfd, address_t * receivedaddressp, port_t * receivedportp, const address_t * sendingaddressp, const port_t sendingport, codex_connection_t * ssl, size_t bufsize, const char * expected)
{
    status_t status = CONTINUE;
    int readfd = -1;
    int writefd = -1;
    int sslfd = -1;
    ssize_t bytes = -1;
    codex_serror_t serror = CODEX_SERROR_NONE;
    int mask = 0;
    int rc = 0;
    const char * label = (const char *)0;

    if (!initialized) {
        diminuto_assert(bufsize > 0);
        buffer[READER] = malloc(bufsize);
        diminuto_assert(buffer[READER] != (void *)0);
        buffer[WRITER] = malloc(bufsize);
        diminuto_assert(buffer[WRITER] != (void *)0);
        initialized = true;
    }

    switch (role) {
    case CLIENT:
        label = "client";
        break;
    case SERVER:
        label = "server";
        break;
    default:
        diminuto_assert(false);
        break;
    }

    diminuto_assert(ssl != (codex_connection_t *)0);
    sslfd = codex_connection_descriptor(ssl);
    diminuto_assert(sslfd >= 0);

    while (fds > 0) {

        readfd = diminuto_mux_ready_read(muxp);
        writefd = diminuto_mux_ready_write(muxp);
fprintf(stderr, "READERWRITER %s fds=%d sslfd=%d udpfd=%d readfd=%d writefd=%d\n", label, fds, sslfd, udpfd, readfd, writefd);

        if (readfd == udpfd) {
            switch (state[WRITER]) {
            case CODEX_STATE_IDLE:
                bytes = datagram_receive(udptype, udpfd, buffer[WRITER], bufsize, receivedaddressp, receivedportp);
                DIMINUTO_LOG_DEBUG("%s: %s writer udp (%d) [%zd] received %s\n", program, label, udpfd, bytes, address2string(udptype, receivedaddressp, *receivedportp));
                if (bytes < 0) {
                    DIMINUTO_LOG_WARNING("%s: %s writer udp (%d) [%zd] error\n", program, label, udpfd, bytes);
                    status = UDPDONE;
                } else if (bytes == 0) {
                    DIMINUTO_LOG_NOTICE("%s: %s writer udp (%d) [%zd] disconnect\n", program, label, udpfd, bytes);
                    status = UDPDONE;
                } else if (bytes > diminuto_maximumof(codex_header_t)) {
                    DIMINUTO_LOG_ERROR("%s: %s writer udp (%d) [%zd] overflow\n", program, label, udpfd, bytes);
                    status = UDPDONE;
                } else {
                    header[WRITER] = bytes;
                    rc = diminuto_mux_register_write(muxp, sslfd);
                    diminuto_assert(rc >= 0);
                    state[WRITER] = restate;
                    restate = CODEX_STATE_RESTART;
                }
                break;
            case CODEX_STATE_FINAL:
                DIMINUTO_LOG_ERROR("%s: %s writer ssl (%d) [%d] final\n", program, label, sslfd, header[WRITER]);
                status = SSLDONE;
                break;
            case CODEX_STATE_COMPLETE:
                DIMINUTO_LOG_ERROR("%s: %s writer ssl (%d) [%d] complete\n", program, label, sslfd, header[WRITER]);
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
                DIMINUTO_LOG_DEBUG("%s: %s writer ssl (%d) [%d] start\n", program, label, sslfd, header[WRITER]);
                /* Fall through. */
            case CODEX_STATE_HEADER:
            case CODEX_STATE_PAYLOAD:
            case CODEX_STATE_SKIP:
                state[WRITER] = codex_machine_writer_generic(state[WRITER], expected, ssl, &(header[WRITER]), buffer[WRITER], header[WRITER], &(here[WRITER]), &(length[WRITER]), &serror, &mask);
                switch (state[WRITER]) {
                case CODEX_STATE_COMPLETE:
                    if (serror == CODEX_SERROR_READ) {
                        DIMINUTO_LOG_NOTICE("%s: %s writer ssl (%d) [%d] needful\n", program, label, sslfd, header[WRITER]);
                    } else {
                        DIMINUTO_LOG_DEBUG("%s: %s writer ssl (%d) [%d] complete\n", program, label, sslfd, header[WRITER]);
                        rc = diminuto_mux_unregister_write(muxp, sslfd);
                        diminuto_assert(rc >= 0);
                        state[WRITER] = CODEX_STATE_IDLE;
                    }
                    break;
                case CODEX_STATE_FINAL:
                    DIMINUTO_LOG_NOTICE("%s: %s writer ssl (%d) [%d] final\n", program, label, sslfd, header[WRITER]);
                    status = SSLDONE;
                    break;
                case CODEX_STATE_IDLE:
                    DIMINUTO_LOG_ERROR("%s: %s writer ssl (%d) [%d] idle\n", program, label, sslfd, header[WRITER]);
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
                DIMINUTO_LOG_ERROR("%s: %s writer ssl (%d) [%d] complete\n", program, label, sslfd, header[WRITER]);
                status = SSLDONE;
                break;
            case CODEX_STATE_FINAL:
                DIMINUTO_LOG_ERROR("%s: %s writer ssl (%d) [%d] final\n", program, label, sslfd, header[WRITER]);
                status = SSLDONE;
                break;
            case CODEX_STATE_IDLE:
                /* Do nothing. */
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
                DIMINUTO_LOG_DEBUG("%s: %s reader ssl (%d) [%d] start\n", program, label, sslfd, header[READER]);
                /* Fall through. */
            case CODEX_STATE_HEADER:
            case CODEX_STATE_PAYLOAD:
            case CODEX_STATE_SKIP:
fprintf(stderr, "READER BEFORE pending=%d\n", codex_connection_is_ready(ssl));
                state[READER] = codex_machine_reader_generic(state[READER], expected, ssl, &(header[READER]), buffer[READER], bufsize, &(here[READER]), &(length[READER]), &serror, &mask);
fprintf(stderr, "READER AFTER pending=%d\n", codex_connection_is_ready(ssl));
                switch (state[READER]) {
                case CODEX_STATE_COMPLETE:
                    if (serror == CODEX_SERROR_WRITE) {
                        DIMINUTO_LOG_NOTICE("%s: %s reader ssl (%d) [%d] needful\n", program, label, sslfd, header[READER]);
                    } else if (header[READER] <= 0) {
                        DIMINUTO_LOG_NOTICE("%s: %s reader ssl (%d) [%d] empty\n", program, label, sslfd, header[READER]);
                        state[READER] = CODEX_STATE_RESTART;
                    } else if (sendingport > 0) {
                        DIMINUTO_LOG_DEBUG("%s: %s reader udp (%d) [%d] sending %s\n", program, label, udpfd, header[READER], address2string(udptype, sendingaddressp, sendingport));
                        bytes = datagram_send(udptype, udpfd, buffer[READER], header[READER], sendingaddressp, sendingport);
                        if (bytes == header[READER]) {
                            DIMINUTO_LOG_DEBUG("%s: %s reader udp (%d) [%zd] restart\n", program, label, udpfd, bytes);
                            state[READER] = CODEX_STATE_RESTART;
                        } else if (bytes == 0) {
                            DIMINUTO_LOG_NOTICE("%s: %s reader udp (%d) [%zd] disconnect\n", program, label, udpfd, bytes);
                            status = UDPDONE;
                        } else {
                            DIMINUTO_LOG_WARNING("%s: %s reader udp (%d) [%zd] error\n", program, label, udpfd, bytes);
                            status = UDPDONE;
                        }
                    } else {
                        DIMINUTO_LOG_INFORMATION("%s: %s reader ssl (%d) [%d] orphan\n", program, label, sslfd, header[READER]);
                        state[READER] = CODEX_STATE_RESTART;
                    }
                    break;
                case CODEX_STATE_FINAL:
                    DIMINUTO_LOG_NOTICE("%s: %s reader ssl (%d) [%d] final\n", program, label, sslfd, header[READER]);
                    status = SSLDONE;
                    break;
                case CODEX_STATE_IDLE:
                    DIMINUTO_LOG_ERROR("%s: %s reader ssl (%d) [%d] idle\n", program, label, sslfd, header[READER]);
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
            case CODEX_STATE_IDLE:
            case CODEX_STATE_FINAL:
                DIMINUTO_LOG_ERROR("%s: %s reader ssl (%d) [%d] fail %c\n", program, label, sslfd, header[READER], state[READER]);
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
        restate = CODEX_STATE_START;
    }

    return status;
}
