/* vi: set ts=4 expandtab shiftwidth=4: */

/**
 * @file
 *
 * Copyright 2023 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 *
 * REFERENCES
 *
 * E. Rescorla, "An Introduction to OpenSSL Programming (Part II)", Version
 * 1.0, 2002-01-09, <http://www.past5.com/assets/post_docs/openssl2.pdf>
 * (also Linux Journal, September 2001)
 */

#include "com/diag/codex/codex.h"
#include "com/diag/diminuto/diminuto_assert.h"
#include "com/diag/diminuto/diminuto_core.h"
#include "com/diag/diminuto/diminuto_ipc.h"
#include "com/diag/diminuto/diminuto_ipc4.h"
#include "com/diag/diminuto/diminuto_ipc6.h"
#include "com/diag/diminuto/diminuto_log.h"
#include "com/diag/diminuto/diminuto_time.h"
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
static ticks_t then = 0;

status_t readerwriter(role_t role, int fds, diminuto_mux_t * muxp, protocol_t udptype, int udpfd, address_t * receivedaddressp, port_t * receivedportp, const address_t * sendingaddressp, const port_t sendingport, codex_connection_t * ssl, size_t bufsize, const char * expected, sticks_t keepalive)
{
    status_t status = CONTINUE;
    int readfd = -1;
    int writefd = -1;
    int sslfd = -1;
    ssize_t bytes = -1;
    codex_serror_t serror = CODEX_SERROR_NONE;
    int mask = 0;
    const char * label = (const char *)0;
    ticks_t now = 0;
    bool pendingssl = false;
    bool needread = false;
    bool needwrite = false;
    int rc = -1;

    if (!initialized) {
        diminuto_assert(bufsize > 0);
        buffer[READER] = malloc(bufsize);
        diminuto_assert(buffer[READER] != (void *)0);
        buffer[WRITER] = malloc(bufsize);
        diminuto_assert(buffer[WRITER] != (void *)0);
        checked = false;
        initialized = true;
        then = diminuto_time_elapsed();
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

        /*
         * Get next socket file descriptors that are ready.
         * See if there is data pending inside the SSL object.
         * Check if SSL needs a write or we need a keep alive.
         */

        readfd = diminuto_mux_ready_read(muxp);
        writefd = diminuto_mux_ready_write(muxp);
        pendingssl = codex_connection_is_ready(ssl);

        DIMINUTO_LOG_DEBUG("%s: %s readfd=(%d) readudp=%d readssl=%d writefd=(%d) writessl=%d pendingssl=%d needread=%d needwrite=%d\n", program, label, readfd, (readfd == udpfd), (readfd == sslfd), writefd, (writefd == sslfd), pendingssl, needread, needwrite);

        /*
         * If we don't seem to have anything to do, return to the caller and
         * let them multiplex us.
         */

        if (readfd >= 0) {
            /* Do nothing. */
        } else if (writefd >= 0) {
            /* Do nothing. */
        } else if (pendingssl) {
            /* Do nothing. */
        } else if (needread) {
            /* Do nothing. */
        } else if (needwrite) {
            /* Do nothing. */
        } else {
            break;
        }

        /*
         * Do UDP reads.
         */

        if (readfd == udpfd) {
            switch (state[WRITER]) {
            case CODEX_STATE_IDLE:
                bytes = datagram_receive(udptype, udpfd, buffer[WRITER], bufsize, receivedaddressp, receivedportp);
                if ((0 < bytes) && (bytes <= bufsize)) {
                    DIMINUTO_LOG_DEBUG("%s: %s writer udp (%d) [%zd] received %s\n", program, label, udpfd, bytes, address2string(udptype, receivedaddressp, *receivedportp));
                    header[WRITER] = bytes;
                    state[WRITER] = restate;
                    restate = CODEX_STATE_RESTART;
                    rc = diminuto_mux_register_write(muxp, sslfd);
                    diminuto_assert(rc >= 0);
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

        /*
         * Do SSL writes.
         */

        if (((writefd == sslfd) && !needread) || ((readfd == sslfd) && needwrite)) {
            needwrite = false;
            switch (state[WRITER]) {
            case CODEX_STATE_START:
            case CODEX_STATE_RESTART:
                DIMINUTO_LOG_DEBUG("%s: %s writer ssl (%d) [%d] start\n", program, label, sslfd, header[WRITER]);
                /* Fall through. */
            case CODEX_STATE_HEADER:
            case CODEX_STATE_PAYLOAD:
                state[WRITER] = codex_machine_writer_generic(state[WRITER], expected, ssl,  &(header[WRITER]), buffer[WRITER], header[WRITER], &(here[WRITER]), &(length[WRITER]), &checked, &serror, &mask);
                switch (serror) {
                case CODEX_SERROR_SUCCESS:
                    switch (state[WRITER]) {
                    case CODEX_STATE_COMPLETE:
                        DIMINUTO_LOG_DEBUG("%s: %s writer ssl (%d) [%d] complete\n", program, label, sslfd, header[WRITER]);
                        state[WRITER] = CODEX_STATE_IDLE;
                        rc = diminuto_mux_unregister_write(muxp, sslfd);
                        diminuto_assert(rc >= 0);
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
                    needread = true;
                    /*
                     * But we're always reading.
                     */
                    break;
                case CODEX_SERROR_WRITE:
                case CODEX_SERROR_NONE:
                    /* Do nothing. */
                    break;
                default:
                    DIMINUTO_LOG_ERROR("%s: %s writer ssl (%d) [%d] error %c %c\n", program, label, sslfd, header[WRITER], (char)state[WRITER], (char)serror);
                    status = SSLDONE;
                    break;
                }
                break;
            case CODEX_STATE_IDLE:
                if (needwrite || ((keepalive >= 0) && ((now = diminuto_time_elapsed()) - then) < keepalive)) {
                    then = now;
                    /*
                     * If the WRITER is IDLE, and the keepalive
                     * has elapsed or we need a write, send an
                     * empty segment (a header containing zero)
                     * to the far end. (This can firehose the log
                     * if DEBUG is enabled and the keepalive is too
                     * small.)
                     */
                    header[WRITER] = 0;
                    DIMINUTO_LOG_DEBUG("%s: %s writer ssl (%d) [%d] keepalive\n", program, label, sslfd, header[WRITER]);
                    state[WRITER] = restate;
                    restate = CODEX_STATE_RESTART;
                    rc = diminuto_mux_register_write(muxp, sslfd);
                    diminuto_assert(rc >= 0);
                }
                break;
            default:
                DIMINUTO_LOG_ERROR("%s: %s writer ssl (%d) [%d] unexpected %c\n", program, label, sslfd, header[WRITER], (char)state[WRITER]);
                status = SSLDONE;
                break;
            }
        }

        if (status != CONTINUE) {
            break;
        }

        /*
         * Do SSL reads and UDP writes.
         */

        if (((readfd == sslfd) && !needwrite) || ((writefd == sslfd) && needwrite) || pendingssl) {
            needread = false;
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
                        needwrite = true;
                        break;
                    case CODEX_SERROR_READ:
                    case CODEX_SERROR_NONE:
                        /* Do nothing. */
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
            } while ((pendingssl = codex_connection_is_ready(ssl)) && !needwrite);
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
