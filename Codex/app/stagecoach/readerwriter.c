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
#include "client.h"
#include "globals.h"
#include "protocols.h"

static bool initialized = false;
static codex_state_t state[DIRECTIONS] = { CODEX_STATE_START, CODEX_STATE_IDLE, };
static codex_state_t restate = CODEX_STATE_START; /* Only for WRITER. */
static codex_header_t header[DIRECTIONS] = { 0, 0, };
static void * buffer[DIRECTIONS] = { (void *)0, (void *)0, };
static uint8_t * here[DIRECTIONS] = { (uint8_t *)0, (uint8_t *)0, };
static size_t length[DIRECTIONS] = { 0, 0, };
static bool checked = false;

status_t readerwriter(role_t role, int fds, diminuto_mux_t * muxp, protocol_t udptype, int udpfd, address_t * receivedaddressp, port_t * receivedportp, const address_t * sendingaddressp, const port_t sendingport, codex_connection_t * ssl, size_t bufsize, const char * expected)
{
    status_t status = CONTINUE;
    int readfd = -1;
    int writefd = -1;
    int sslfd = -1;
    ssize_t bytes = -1;
    codex_serror_t serror = CODEX_SERROR_NONE;
    int mask = 0;
    const char * label = (const char *)0;
    bool pending = false;

    if (!initialized) {
        diminuto_assert(bufsize > 0);
        buffer[READER] = malloc(bufsize);
        diminuto_assert(buffer[READER] != (void *)0);
        buffer[WRITER] = malloc(bufsize);
        diminuto_assert(buffer[WRITER] != (void *)0);
        checked = false;
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

    do {

        readfd = diminuto_mux_ready_read(muxp);
        writefd = diminuto_mux_ready_write(muxp);
        pending = codex_connection_is_ready(ssl);

        if (readfd >= 0) {
            /* Do nothing. */
        } else if (writefd >= 0) {
            /* Do nothing. */
        } else if (pending) {
            /* Do nothing. */
        } else {
            break;
        }

        if (readfd == udpfd) {
            switch (state[WRITER]) {
            case CODEX_STATE_IDLE:
                bytes = datagram_receive(udptype, udpfd, buffer[WRITER], bufsize, receivedaddressp, receivedportp);
                if ((0 < bytes) && (bytes <= bufsize)) {
                    DIMINUTO_LOG_DEBUG("%s: %s writer udp (%d) [%zd] received %s\n", program, label, udpfd, bytes, address2string(udptype, receivedaddressp, *receivedportp));
                    header[WRITER] = bytes;
                    state[WRITER] = restate;
                    restate = CODEX_STATE_RESTART;
                } else {
                    DIMINUTO_LOG_NOTICE("%s: %s writer udp (%d) [%zd] error\n", program, label, udpfd, bytes);
                    status = UDPDONE;
                }
                break;
            default:
                /* Do nothing. */
                break;
            }
        }

        if (status != CONTINUE) {
            break;
        }

        if (writefd == sslfd) {
            switch (state[WRITER]) {
            case CODEX_STATE_START:
            case CODEX_STATE_RESTART:
                DIMINUTO_LOG_DEBUG("%s: %s writer ssl (%d) [%d] start\n", program, label, sslfd, header[WRITER]);
                /* Fall through. */
            case CODEX_STATE_HEADER:
            case CODEX_STATE_PAYLOAD:
                state[WRITER] = codex_machine_writer_generic(state[WRITER], expected, ssl, &(header[WRITER]), buffer[WRITER], header[WRITER], &(here[WRITER]), &(length[WRITER]), &checked, &serror, &mask);
                switch (serror) {
                case CODEX_SERROR_SUCCESS:
                    switch (state[WRITER]) {
                    case CODEX_STATE_COMPLETE:
                        DIMINUTO_LOG_DEBUG("%s: %s writer ssl (%d) [%d] complete\n", program, label, sslfd, header[WRITER]);
                        state[WRITER] = CODEX_STATE_IDLE;
                        break;
                    case CODEX_STATE_FINAL:
                    case CODEX_STATE_IDLE:
                        DIMINUTO_LOG_NOTICE("%s: %s writer ssl (%d) [%d] final %c\n", program, label, sslfd, header[WRITER], (char)state[WRITER]);
                        status = SSLDONE;
                        break;
                    default:
                        /* Do nothing. */
                        break;
                    }
                    break;
                case CODEX_SERROR_READ:
                    DIMINUTO_LOG_NOTICE("%s: %s writer ssl (%d) [%d] need read\n", program, label, sslfd, header[WRITER]);
                    break;
                default:
                    DIMINUTO_LOG_ERROR("%s: %s writer ssl (%d) [%d] error %c %c\n", program, label, sslfd, header[WRITER], (char)state[WRITER], (char)serror);
                    status = SSLDONE;
                    break;
                }
                break;
            case CODEX_STATE_COMPLETE:
            case CODEX_STATE_FINAL:
                DIMINUTO_LOG_ERROR("%s: %s writer ssl (%d) [%d] unexpected %c\n", program, label, sslfd, header[WRITER], (char)state[WRITER]);
                status = SSLDONE;
                break;
            case CODEX_STATE_IDLE:
                header[WRITER] = 0;
#if 0
                /*
                 * Even DEBUG is too much of a firehose.
                 */
                DIMINUTO_LOG_DEBUG("%s: %s writer ssl (%d) [%d] synthesize\n", program, label, sslfd, header[WRITER]);
#endif
                state[WRITER] = restate;
                restate = CODEX_STATE_RESTART;
                break;
            }
        }

        if (status != CONTINUE) {
            break;
        }

        if ((readfd == sslfd) || pending) {
            do {
                switch (state[READER]) {
                case CODEX_STATE_START:
                case CODEX_STATE_RESTART:
                    DIMINUTO_LOG_DEBUG("%s: %s reader ssl (%d) [%d] start\n", program, label, sslfd, header[READER]);
                    /* Fall through. */
                case CODEX_STATE_HEADER:
                case CODEX_STATE_PAYLOAD:
                    state[READER] = codex_machine_reader_generic(state[READER], expected, ssl, &(header[READER]), buffer[READER], bufsize, &(here[READER]), &(length[READER]), &checked, &serror, &mask);
                    switch (serror) {
                    case CODEX_SERROR_SUCCESS:
                        switch (state[READER]) {
                        case CODEX_STATE_COMPLETE:
                            if (header[READER] > 0) {
                                DIMINUTO_LOG_DEBUG("%s: %s reader udp (%d) [%d] sending %s\n", program, label, udpfd, header[READER], address2string(udptype, sendingaddressp, sendingport));
                                bytes = datagram_send(udptype, udpfd, buffer[READER], header[READER], sendingaddressp, sendingport);
                                if (bytes == header[READER]) {
                                    state[READER] = CODEX_STATE_RESTART;
                                } else {
                                    DIMINUTO_LOG_NOTICE("%s: %s reader udp (%d) [%zd] error\n", program, label, udpfd, bytes);
                                    status = UDPDONE;
                                }
                            } else {
                                /*
                                 * This should never happen because the lower
                                 * layers already filter out zero-length
                                 * packets. But if it does happen, it is such
                                 * a firehose that we limit it to DEBUG level.
                                 */
                                DIMINUTO_LOG_DEBUG("%s: %s reader ssl (%d) [%d] empty\n", program, label, sslfd, header[READER]);
                                state[READER] = CODEX_STATE_RESTART;
                            }
                            break;
                        case CODEX_STATE_FINAL:
                        case CODEX_STATE_IDLE:
                            DIMINUTO_LOG_NOTICE("%s: %s reader ssl (%d) [%d] final %c\n", program, label, sslfd, header[READER], (char)state[READER]);
                            status = SSLDONE;
                            break;
                        default:
                            /* Do nothing. */
                            break;
                        }
                        break;
                    case CODEX_SERROR_WRITE:
                        DIMINUTO_LOG_NOTICE("%s: %s reader ssl (%d) [%d] need write\n", program, label, sslfd, header[READER]);
                        switch (state[WRITER]) {
                        case CODEX_STATE_IDLE:
                            header[WRITER] = 0;
                            state[WRITER] = restate;
                            restate = CODEX_STATE_RESTART;
                            break;
                        default:
                            /* Do nothing. */
                            break;
                        }
                        break;
                    default:
                        DIMINUTO_LOG_ERROR("%s: %s reader ssl (%d) [%d] error %c %c\n", program, label, sslfd, header[READER], (char)state[READER], (char)serror);
                        status = SSLDONE;
                        break;
                    }
                    break;
                case CODEX_STATE_COMPLETE:
                case CODEX_STATE_IDLE:
                case CODEX_STATE_FINAL:
                    DIMINUTO_LOG_ERROR("%s: %s reader ssl (%d) [%d] unexpected %c\n", program, label, sslfd, header[READER], (char)state[READER]);
                    status = SSLDONE;
                    break;
                }
                if (status != CONTINUE) {
                    break;
                }
                /*
                 * Consume all the data in the SSL pipeline.
                 */
            } while (codex_connection_is_ready(ssl));
        }

    } while (status == CONTINUE);

    if (status != CONTINUE) {
        state[READER] = CODEX_STATE_START;
        state[WRITER] = CODEX_STATE_IDLE;
        restate = CODEX_STATE_START;
        checked = false;
    }

    return status;
}
