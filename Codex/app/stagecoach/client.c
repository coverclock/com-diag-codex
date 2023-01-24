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
#include "client.h"
#include "globals.h"

int client(diminuto_mux_t * muxp, protocol_t udptype, int udpfd, codex_connection_t * ssl)
{
    /**/
    static bool initialized = false;
    static codex_state_t states[DIRECTIONS] = { CODEX_STATE_START, CODEX_STATE_COMPLETE, };
    static codex_header_t headers[DIRECTIONS] = { 0, 0, };
    static void * buffers[DIRECTIONS] = { (void *)0, (void *)0, };
    static uint8_t * heres[DIRECTIONS] = { (uint8_t *)0, (uint8_t *)0, };
    static size_t lengths[DIRECTIONS] = { 0, 0, };
    static bool pending = false;
    static bool first = true;
    static diminuto_port_t last = 0;
    /**/
    int muxfd = -1;
    codex_state_t state = CODEX_STATE_FINAL;
    int rc = -1;
    ssize_t bytes = -1;

    if (!initialized) {
        buffers[READER] = malloc(bufsize);
        diminuto_assert(buffers[READER] != (void *)0);
        buffers[WRITER] = malloc(bufsize);
        diminuto_assert(buffers[WRITER] != (void *)0);
        initialized = true;
    }

    muxfd = diminuto_mux_ready_write(&mux);
    if (muxfd == codex_connection_descriptor(ssl)) {

        if (states[WRITER] == CODEX_STATE_COMPLETE) {
            /* Do nothing. */
        } else if (states[WRITER] == CODEX_STATE_IDLE) {
            /* Do nothing. */
        } else {

            state = codex_machine_writer(states[WRITER], expected, ssl, &(headers[WRITER]), buffers[WRITER], headers[WRITER], &(heres[WRITER]), &(lengths[WRITER]));

            if (state == CODEX_STATE_FINAL) {
                break;
            } else if (state == states[WRITER]) {
                /* Do nothing. */
            } else if (state != CODEX_STATE_COMPLETE) {
                /* Do nothing. */
            } else {

                DIMINUTO_LOG_DEBUG("%s: %s write (%d) [%d]\n", program, name, muxfd, headers[WRITER]);

            }

            states[WRITER] = state;

        }

    } else {
        /* Do nothing. */
    }

    muxfd = diminuto_mux_ready_read(&mux);
    if (muxfd == codex_connection_descriptor(ssl)) {

        if (states[READER] == CODEX_STATE_COMPLETE) {
            /* Cannot happen. */
        } else if (states[READER] == CODEX_STATE_IDLE) {
            /* Do nothing. */
        } else {

            do {

                state = codex_machine_reader(states[READER], expected, ssl, &(headers[READER]), buffers[READER], bufsize, &(heres[READER]), &(lengths[READER]));

                if (state == CODEX_STATE_FINAL) {
                    /* Do nothing. */
                } else if (state != CODEX_STATE_COMPLETE) {
                    /* Do nothing. */
                } else {

                    DIMINUTO_LOG_DEBUG("%s: %s read (%d) [%d]\n", program, muxfd, headers[READER]);

                    bytes = diminuto_fd_write_generic(STDOUT_FILENO, buffers[READER], headers[READER], headers[READER]);
                    if (bytes <= 0) {
                        break;
                    }

                    state = CODEX_STATE_RESTART;

                    if (pending)  {
                        states[WRITER] = CODEX_STATE_START;
                        pending = false;
                    }

                }

                states[READER] = state;

                if (state == CODEX_STATE_IDLE) {
                    break;
                } else if (state == CODEX_STATE_FINAL) {
                    break;
                } else {
                    /* Do nothing. */
                }

            } while (codex_connection_is_ready(ssl));

        }

    } else if (fd == STDIN_FILENO) {

        if (states[WRITER] == CODEX_STATE_COMPLETE) {

            bytes = diminuto_fd_read(STDIN_FILENO, buffers[WRITER], bufsize);
            if (bytes <= 0) {
                DIMINUTO_LOG_INFORMATION("%s: EOF fd=%d\n", program, STDIN_FILENO);
                rc = diminuto_mux_unregister_read(&mux, STDIN_FILENO);
                ASSERT(rc >= 0);
                eof = true;
                continue;
            }

            headers[WRITER] = bytes;

            if (first) {
                states[WRITER] = CODEX_STATE_START;
                first = false;
            } else {
                states[WRITER] = CODEX_STATE_RESTART;
            }

        }

    } else {
        /* Do nothing. */
    }

    return -1;
}
