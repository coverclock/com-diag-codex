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
#include "com/diag/diminuto/diminuto_minmaxof.h"
#include "com/diag/diminuto/diminuto_mux.h"
#include "com/diag/diminuto/diminuto_time.h"
#include "globals.h"
#include "helpers.h"
#include <stdio.h>
#include <unistd.h>

static bool checked = false;
static bool initialized = false;
static bool reintroduce = false;
static bool neareof = false;
static bool fareof = false;
static bool needread = false;
static bool needwrite = false;
static codex_state_t state[DIRECTIONS] = { CODEX_STATE_START, CODEX_STATE_IDLE, };
static codex_state_t restate = CODEX_STATE_START; /* Only for WRITER. */
static codex_header_t header[DIRECTIONS] = { 0, 0, };
static void * buffer[DIRECTIONS] = { (void *)0, (void *)0, };
static uint8_t * here[DIRECTIONS] = { (uint8_t *)0, (uint8_t *)0, };
static size_t length[DIRECTIONS] = { 0, 0, };
static ssize_t size[DIRECTIONS] = { 0, 0, };
static ticks_t then = 0;

void readerwriterfini(void)
{
    free(buffer[READER]);
    free(buffer[WRITER]);
}

status_t readerwriter(role_t role, bool introduce, int fds, diminuto_mux_t * muxp, int inpfd, codex_connection_t * ssl, int outfd, size_t bufsize, const char * expected, sticks_t keepalive)
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
    int rc = -1;

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

    if (!initialized) {
        diminuto_assert(bufsize > 0);
        diminuto_assert(bufsize <= maximumof(codex_header_t));
        buffer[READER] = malloc(bufsize); /* For the SSL stream. */
        size[READER] = bufsize;
        diminuto_assert(buffer[READER] != (void *)0);
        buffer[WRITER] = malloc(bufsize); /* For the stdin stream. */
        diminuto_assert(buffer[WRITER] != (void *)0);
        checked = false;
        then = diminuto_time_elapsed();
        initialized = true;
        reintroduce = introduce;
    }

    if (reintroduce) {
        size[WRITER] = CODEX_INDICATION_NONE;
        state[WRITER] = restate;
        restate = CODEX_STATE_RESTART;
        rc = diminuto_mux_register_write(muxp, sslfd);
        diminuto_assert(rc >= 0);
        reintroduce = false;
    }

    do {

        /*
         * Get next socket file descriptors that are ready.
         * See if there is data pending inside the SSL object.
         * Check if SSL needs a write or we need a keep alive.
         */

        readfd = diminuto_mux_ready_read(muxp);
        writefd = diminuto_mux_ready_write(muxp);
        pendingssl = codex_connection_is_ready(ssl);

        DIMINUTO_LOG_DEBUG("%s: %s inpfd=%d outfd=%d sslfd=%d readfd=%d writefd=%d pendingssl=%d needread=%d needwrite=%d neareof=%d fareof=%d reader=%c[%ld] writer=%c[%ld]\n", program, name, inpfd, outfd, sslfd, readfd, writefd, pendingssl, needread, needwrite, neareof, fareof, state[READER], size[READER], state[WRITER], size[WRITER]);

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

        if (readfd == inpfd) {

            switch (state[WRITER]) {
            case CODEX_STATE_IDLE:
                bytes = read(inpfd, buffer[WRITER], bufsize);
                if ((0 < bytes) && (bytes <= bufsize)) {
                    size[WRITER] = bytes;
                    state[WRITER] = restate;
                    restate = CODEX_STATE_RESTART;
                    rc = diminuto_mux_register_write(muxp, sslfd);
                    diminuto_assert(rc >= 0);
                } else if (bytes == 0) {
                    rc = diminuto_mux_unregister_read(muxp, inpfd);
                    diminuto_assert(rc >= 0);
                    neareof = true;
                    size[WRITER] = CODEX_INDICATION_DONE;
                    state[WRITER] = restate;
                    restate = CODEX_STATE_RESTART;
                    rc = diminuto_mux_register_write(muxp, sslfd);
                    diminuto_assert(rc >= 0);
                    DIMINUTO_LOG_DEBUG("%s: %s nearend (%d) eof\n", program, name, inpfd);
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

            if (status != CONTINUE) {
                break;
            }

        }

        /*
         * Do SSL writes.
         */

        if (((writefd == sslfd) && !needread) || ((readfd == sslfd) && needwrite)) {

            switch (state[WRITER]) {
            case CODEX_STATE_IDLE:
                if (needwrite || ((keepalive >= 0) && ((now = diminuto_time_elapsed()) - then) < keepalive)) {
                    then = now;
                    /*
                     * If the WRITER is IDLE, and the keepalive
                     * has elapsed or we need a write, send an
                     * empty segment (a header containing zero)
                     * to the far end. (This can firehose the log
                     * if DEBUG is enabled and the keepalive is too
                     * small.) If we need to signal the other end
                     * that we've reached end-of-file, send a DONE.
                     */
                    size[WRITER] = CODEX_INDICATION_NONE;
                    state[WRITER] = restate;
                    restate = CODEX_STATE_RESTART;
                    rc = diminuto_mux_register_write(muxp, sslfd);
                    diminuto_assert(rc >= 0);
                    /* Fall through. */
                } else {
                    break;
                }
            case CODEX_STATE_INIT:
                /* Fall through. */
            case CODEX_STATE_START:
            case CODEX_STATE_RESTART:
                /* Fall through. */
            case CODEX_STATE_HEADER:
            case CODEX_STATE_PAYLOAD:
                state[WRITER] = codex_machine_writer_generic(state[WRITER], expected, ssl,  &(header[WRITER]), buffer[WRITER], size[WRITER], &(here[WRITER]), &(length[WRITER]), &checked, &serror, &mask);
                needwrite = false;
                switch (serror) {
                case CODEX_SERROR_SUCCESS:
                    switch (state[WRITER]) {
                    case CODEX_STATE_COMPLETE:
                        state[WRITER] = CODEX_STATE_IDLE;
                        rc = diminuto_mux_unregister_write(muxp, sslfd);
                        diminuto_assert(rc >= 0);
                        DIMINUTO_LOG_DEBUG("%s: %s sent (%d) [%ld]\n", program, name, sslfd, size[WRITER]);
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
            default:
                status = SSLDONE;
                break;
            }

            if (status != CONTINUE) {
                break;
            }

        }

        /*
         * Do SSL reads and stdout writes.
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
                    state[READER] = codex_machine_reader_generic(state[READER], expected, ssl, &(header[READER]), buffer[READER], size[READER], &(here[READER]), &(length[READER]), &checked, &serror, &mask);
                    needread = false;
                    switch (serror) {
                    case CODEX_SERROR_SUCCESS:
                        switch (state[READER]) {
                        case CODEX_STATE_COMPLETE:
                            DIMINUTO_LOG_DEBUG("%s: %s received (%d) [%d]\n", program, name, sslfd, header[READER]);
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
                            } else if (header[READER] < 0) {
                                state[READER] = CODEX_STATE_IDLE;
                                fareof = true;
                                DIMINUTO_LOG_DEBUG("%s: %s farend (%d) eof\n", program, name, sslfd);
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

                if (!neareof) {
                    /* Do nothing. */
                } else if (!fareof) {
                    /* Do nothing. */
                } else if (state[WRITER] != CODEX_STATE_IDLE) {
                    /* Do nothing. */
                } else {
                    status = ALLDONE;
                    DIMINUTO_LOG_DEBUG("%s: %s quiescent\n", program, name);
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
        reintroduce = introduce;
    }

    return status;
}
