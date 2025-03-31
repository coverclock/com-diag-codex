/* vi: set ts=4 expandtab shiftwidth=4: */

/**
 * @file
 *
 * Copyright 2023-2025 Digital Aggregates Corporation, Colorado, USA<BR>
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
#include "com/diag/diminuto/diminuto_log.h"
#include "com/diag/diminuto/diminuto_mux.h"
#include "com/diag/diminuto/diminuto_time.h"
#include "globals.h"
#include "helpers.h"
#include <stdio.h>
#include <unistd.h>

static bool initialized = false;
static codex_state_t state[DIRECTIONS] = { CODEX_STATE_START, CODEX_STATE_IDLE, };
static codex_state_t restate = CODEX_STATE_START; /* Only for WRITER. */
static codex_header_t header[DIRECTIONS] = { 0, 0, };
static void * buffer[DIRECTIONS] = { (void *)0, (void *)0, };
static uint8_t * here[DIRECTIONS] = { (uint8_t *)0, (uint8_t *)0, };
static size_t length[DIRECTIONS] = { 0, 0, };
static bool checked = false;
static ticks_t then = 0;

status_t readerwriter(role_t role, int fds, diminuto_mux_t * muxp, int infd, codex_connection_t * ssl, int outfd, size_t bufsize, const char * expected, sticks_t keepalive)
{
    status_t status = CONTINUE;
    int readfd = -1;
    int writefd = -1;
    int sslfd = -1;
    ssize_t bytes = -1;
    codex_serror_t serror = CODEX_SERROR_NONE;
    int mask = 0;
    const char * name = (const char *)0;
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
        name = "codextoolclient";
        break;
    case SERVER:
        name = "codextoolserver";
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

        DIMINUTO_LOG_DEBUG("%s: %s readfd=(%d) readstdin=%d readssl=%d writefd=(%d) writestdout=%d writessl=%d pendingssl=%d needread=%d needwrite=%d\n", program, name, readfd, (readfd == infd), (readfd == sslfd), writefd, (writefd == outfd), (writefd == sslfd), pendingssl, needread, needwrite);

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
         * Do stdin reads.
         */

        if (readfd == infd) {
            switch (state[WRITER]) {
            case CODEX_STATE_IDLE:
                bytes = read(infd, buffer[WRITER], bufsize);
                if ((0 < bytes) && (bytes <= bufsize)) {
                    header[WRITER] = bytes;
                    state[WRITER] = restate;
                    restate = CODEX_STATE_RESTART;
                    rc = diminuto_mux_register_write(muxp, sslfd);
                    diminuto_assert(rc >= 0);
                } else if (bytes == 0) {
                    errno = 0;
                    status = STDDONE;
                } else if (bytes > bufsize) {
                    errno = EINVAL;
                    diminuto_perror("read");
                    status = STDDONE;
                } else {
                    diminuto_perror("read");
                    status = STDDONE;
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
            switch (state[WRITER]) {
            case CODEX_STATE_INIT:
                /* Fall through. */
            case CODEX_STATE_START:
            case CODEX_STATE_RESTART:
                /* Fall through. */
            case CODEX_STATE_HEADER:
            case CODEX_STATE_PAYLOAD:
                state[WRITER] = codex_machine_writer_generic(state[WRITER], expected, ssl,  &(header[WRITER]), buffer[WRITER], header[WRITER], &(here[WRITER]), &(length[WRITER]), &checked, &serror, &mask);
                needwrite = false;
                switch (serror) {
                case CODEX_SERROR_SUCCESS:
                    switch (state[WRITER]) {
                    case CODEX_STATE_COMPLETE:
                        state[WRITER] = CODEX_STATE_IDLE;
                        rc = diminuto_mux_unregister_write(muxp, sslfd);
                        diminuto_assert(rc >= 0);
                        break;
                    case CODEX_STATE_FINAL:
                    case CODEX_STATE_IDLE:
                        status = SSLDONE;
                        break;
                    default:
                        /* Do nothing. */
                        break;
                    }
                    break;
                case CODEX_SERROR_READ:
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
                    state[WRITER] = restate;
                    restate = CODEX_STATE_RESTART;
                    rc = diminuto_mux_register_write(muxp, sslfd);
                    diminuto_assert(rc >= 0);
                }
                break;
            default:
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

        if (((readfd == sslfd) && !needwrite) || ((writefd == sslfd) && needread) || pendingssl) {
            do {
                switch (state[READER]) {
                case CODEX_STATE_INIT:
                    /* Fall through. */
                case CODEX_STATE_START:
                case CODEX_STATE_RESTART:
                    /* Fall through. */
                case CODEX_STATE_HEADER:
                case CODEX_STATE_PAYLOAD:
                    state[READER] = codex_machine_reader_generic(state[READER], expected, ssl, &(header[READER]), buffer[READER], bufsize, &(here[READER]), &(length[READER]), &checked, &serror, &mask);
                    needread = false;
                    switch (serror) {
                    case CODEX_SERROR_SUCCESS:
                        switch (state[READER]) {
                        case CODEX_STATE_COMPLETE:
                            if (header[READER] > 0) {
                                bytes = write(outfd, buffer[READER], header[READER]);
                                if (bytes == header[READER]) {
                                    state[READER] = CODEX_STATE_RESTART;
                                } else if (bytes == 0) {
                                    errno = 0;
                                    status = STDDONE;
                                } else if (bytes > header[READER]) {
                                    errno = EINVAL;
                                    diminuto_perror("write");
                                    status = STDDONE;
                                } else {
                                    diminuto_perror("write");
                                    status = STDDONE;
                                }
                            } else {
                                /*
                                 * This should never happen because the lower
                                 * layers already filter out zero-length
                                 * packets. But if it does happen, it is such
                                 * a firehose that we limit it to DEBUG level.
                                 */
                                state[READER] = CODEX_STATE_RESTART;
                            }
                            break;
                        case CODEX_STATE_FINAL:
                        case CODEX_STATE_IDLE:
                            status = SSLDONE;
                            break;
                        default:
                            /* Do nothing. */
                            break;
                        }
                        break;
                    case CODEX_SERROR_WRITE:
                        needwrite = true;
                        break;
                    case CODEX_SERROR_READ:
                    case CODEX_SERROR_NONE:
                        /* Do nothing. */
                        break;
                    default:
                        status = SSLDONE;
                        break;
                    }
                    break;
                case CODEX_STATE_COMPLETE:
                case CODEX_STATE_IDLE:
                case CODEX_STATE_FINAL:
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
