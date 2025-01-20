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
#include "com/diag/diminuto/diminuto_mux.h"
#include "com/diag/diminuto/diminuto_delay.h"
#include "com/diag/diminuto/diminuto_hangup.h"
#include "com/diag/diminuto/diminuto_fletcher.h"
#include "com/diag/diminuto/diminuto_timer.h"
#include "com/diag/diminuto/diminuto_frequency.h"
#include "com/diag/diminuto/diminuto_alarm.h"
#include "com/diag/diminuto/diminuto_fd.h"
#include "com/diag/diminuto/diminuto_pipe.h"
#include "com/diag/diminuto/diminuto_ipc6.h"
#include "com/diag/codex/codex.h"
#include "unittest-codex.h"
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

static const char * program = "unittest-handshake-client";
static const char * farend = "localhost:49202";
static const char * expected = "server.prairiethorn.org";
static diminuto_ticks_t period = 0;
static size_t bufsize = 256;
static const char * pathcaf = COM_DIAG_CODEX_OUT_CRT_PATH "/" "root.pem";
static const char * pathcap = (const char *)0;
static const char * pathcrl = (const char *)0;
static const char * pathcrt = COM_DIAG_CODEX_OUT_CRT_PATH "/" "client.pem";
static const char * pathkey = COM_DIAG_CODEX_OUT_CRT_PATH "/" "client.pem";
static const char * pathdhf = COM_DIAG_CODEX_OUT_CRT_PATH "/" "dh.pem";
static int selfsigned = -1;

int main(int argc, char ** argv)
{
    static const int READER = 0;
    static const int WRITER = 1;
    codex_state_t states[2] = { CODEX_STATE_RESTART, CODEX_STATE_IDLE };
    void * buffers[2] = { (void *)0, (void *)0 };
    codex_header_t headers[2] = { 0, 0 };
    uint8_t * heres[2] = { (uint8_t *)0, (uint8_t *)0 };
    size_t lengths[2] = { 0, 0 };
    bool checked = false;
    codex_connection_t * ssl = (codex_connection_t *)0;
    int rc = -1;
    codex_context_t * ctx = (codex_context_t *)0;
    diminuto_mux_t mux = { 0 };
    int fd = -1;
    ssize_t bytes = -1;
    bool eof = false;
    uint64_t input = 0;
    uint64_t output = 0;
    char * endptr = (char *)0;
    uint16_t f16source = 0;
    uint8_t f16sourceA = 0;
    uint8_t f16sourceB = 0;
    uint16_t f16sink = 0;
    uint8_t f16sinkA = 0;
    uint8_t f16sinkB = 0;
    diminuto_sticks_t ticks = -1;
    codex_indication_t indication = CODEX_INDICATION_NONE;
    bool verify = true;
    diminuto_ipv6_t addressne = { 0 };
    diminuto_port_t portne = 0;
    diminuto_ipv6_t addressfe = { 0 };
    diminuto_port_t portfe = 0;
    char bufferne[sizeof("XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX")];
    char bufferfe[sizeof("XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:XXXX")];
    int opt = '\0';
    extern char * optarg;

    (void)diminuto_core_enable();

    diminuto_log_setmask();

    program = ((program = strrchr(argv[0], '/')) == (char *)0) ? argv[0] : program + 1;

    while ((opt = getopt(argc, argv, "B:C:D:K:L:P:R:Sf:e:p:s?")) >= 0) {

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

        case 'f':
            farend = optarg;
            break;

        case 'p':
            period = strtol(optarg, &endptr, 0);
            break;

        case 's':
            selfsigned = 1;
            break;

        case '?':
            fprintf(stderr, "usage: %s [ -B BUFSIZE ] [ -C CERTIFICATEFILE ] [ -D DHPARMSFILE ] [ -K PRIVATEKEYFILE ] [ -L REVOCATIONFILE ] [ -P CERTIFICATESPATH ] [ -R ROOTFILE ] [ -e EXPECTED ] [ -f FAREND ] [ -p SECONDS ] [ -S | -s ]\n", program);
            return 1;
            break;

        }

    }

    DIMINUTO_LOG_INFORMATION("%s: BEGIN B=%zu C=\"%s\" D=\"%s\" K=\"%s\" L=\"%s\" P=\"%s\" R=\"%s\" f=\"%s\" e=\"%s\" p=%llu s=%d\n", program, bufsize, pathcrt, pathdhf, pathkey, (pathcrl == (const char *)0) ? "" : pathcrl, (pathcap == (const char *)0) ? "" : pathcap, (pathcaf == (const char *)0) ? "" : pathcaf, farend, (expected == (const char *)0) ? "" : expected, (diminuto_llu_t)period, selfsigned);

    rc = diminuto_hangup_install(!0);
    ASSERT(rc == 0);

    if (period > 0) {

        rc = diminuto_alarm_install(!0);
        ASSERT(rc == 0);

         ticks = diminuto_timer_periodic(period * diminuto_frequency());
        ASSERT(ticks >= 0);

    }

    rc = diminuto_pipe_install(!0);
    ASSERT(rc == 0);

    buffers[READER] = malloc(bufsize);
    ASSERT(buffers[READER] != (uint8_t *)0);

    buffers[WRITER] = malloc(bufsize);
    ASSERT(buffers[WRITER] != (uint8_t *)0);

    if (selfsigned >= 0) {
        extern int codex_set_self_signed_certificates(int);
        codex_set_self_signed_certificates(!!selfsigned);
    }

    rc = codex_initialize(pathdhf, pathcrl);
    ASSERT(rc == 0);

    ctx = codex_client_context_new(pathcaf, pathcap, pathcrt, pathkey);
    ASSERT(ctx != (SSL_CTX *)0);

    ssl = codex_client_connection_new(ctx, farend);
    ASSERT(ssl != (SSL *)0);
    EXPECT(!codex_connection_is_server(ssl));

    fd = codex_connection_descriptor(ssl);
    ASSERT(fd >= 0);
    ASSERT(fd != STDIN_FILENO);
    ASSERT(fd != STDOUT_FILENO);

    rc = diminuto_ipc6_nearend(fd, &addressne, &portne);
    EXPECT(rc == 0);
    rc = diminuto_ipc6_farend(fd, &addressfe, &portfe);
    EXPECT(rc == 0);
    DIMINUTO_LOG_INFORMATION("%s: START nearend=[%s]:%d farend=[%s]:%d\n", program, diminuto_ipc6_address2string(addressne, bufferne, sizeof(bufferne)), portne, diminuto_ipc6_address2string(addressfe, bufferfe, sizeof(bufferfe)), portfe);

    diminuto_mux_init(&mux);

    rc = diminuto_mux_register_read(&mux, fd);
    ASSERT(rc >= 0);

    rc = diminuto_mux_register_write(&mux, fd);
    ASSERT(rc >= 0);

    rc = diminuto_mux_register_read(&mux, STDIN_FILENO);
    ASSERT(rc >= 0);

    eof = false;
    input = 0;
    output = 0;
    while ((!eof) || (output < input)) {

        if (diminuto_alarm_check()) {
            DIMINUTO_LOG_INFORMATION("%s: SIGALRM eof=%d input=%llu output=%llu f16source=0x%4.4x f16sink=0x%4.4x indication=%d\n", program, eof, ULL(input), ULL(output), f16sink, f16source, indication);
        }

        if (diminuto_hangup_check()) {
            DIMINUTO_LOG_INFORMATION("%s: SIGHUP\n", program);
            if (indication == CODEX_INDICATION_NONE) {
                indication = CODEX_INDICATION_NEAREND;
            }
        }

        if (diminuto_pipe_check()) {
            DIMINUTO_LOG_INFORMATION("%s: SIGPIPE\n", program);
            /* Unimplemented. */
        }

        rc = diminuto_mux_wait(&mux, -1);
        if ((rc == 0) || ((rc < 0) && (errno == EINTR))) {
            diminuto_yield();
            continue;
        }
        ASSERT(rc > 0);

        while ((fd = diminuto_mux_ready_write(&mux)) >= 0) {

            if (fd == codex_connection_descriptor(ssl)) {

                if (states[WRITER] != CODEX_STATE_IDLE) {

                    states[WRITER] = codex_machine_writer(states[WRITER], expected, ssl, &(headers[WRITER]), buffers[WRITER], headers[WRITER], &(heres[WRITER]), &(lengths[WRITER]), &checked);

                    if (states[WRITER] == CODEX_STATE_FINAL) {

                        DIMINUTO_LOG_INFORMATION("%s: FINAL\n", program);
                        break;

                    }

                    if (states[WRITER] == CODEX_STATE_COMPLETE) {

                        DIMINUTO_LOG_DEBUG("%s: WRITE DATA header=%d state=`%c` indication=%d\n", program, headers[WRITER], states[WRITER], indication);

                        if (indication == CODEX_INDICATION_NONE) {

                            states[WRITER] = CODEX_STATE_IDLE;

                        } else if (headers[WRITER] == CODEX_INDICATION_FAREND) {

                            states[WRITER] = CODEX_STATE_IDLE;

                        } else if (indication == CODEX_INDICATION_NEAREND) {

                            headers[WRITER] = CODEX_INDICATION_FAREND;
                            states[WRITER] = CODEX_STATE_RESTART;
                            DIMINUTO_LOG_INFORMATION("%s: WRITE FAREND header=%d state=`%c` indication=%d\n", program, headers[WRITER], states[WRITER], indication);

                        } else {

                            states[WRITER] = CODEX_STATE_IDLE;

                        }

                    }

                }

            } else {

                FATAL();

            }

        }

        if (states[WRITER] == CODEX_STATE_FINAL) {
            break;
        }

        while ((fd = diminuto_mux_ready_read(&mux)) >= 0) {

            if (fd == codex_connection_descriptor(ssl)) {

                if (states[READER] != CODEX_STATE_IDLE) {

                    do {

                        states[READER] = codex_machine_reader(states[READER], expected, ssl, &(headers[READER]), buffers[READER], bufsize, &(heres[READER]), &(lengths[READER]), &checked);

                        if (states[READER] == CODEX_STATE_FINAL) {

                            DIMINUTO_LOG_INFORMATION("%s: FINAL\n", program);
                            break;

                        }

                        if (states[READER] == CODEX_STATE_COMPLETE) {

                            DIMINUTO_LOG_DEBUG("%s: READ DATA header=%d state=`%c` indication=%d\n", program, headers[READER], states[READER], indication);

                            if (headers[READER] >= 0) {

                                f16sink = diminuto_fletcher_16(buffers[READER], headers[READER], &f16sinkA, &f16sinkB);
                                output += headers[READER];

                                bytes = diminuto_fd_write_generic(STDOUT_FILENO, buffers[READER], headers[READER], headers[READER]);
                                if (bytes <= 0) {
                                    DIMINUTO_LOG_INFORMATION("%s: EOF fd=%d\n", program, STDOUT_FILENO);
                                    break;
                                }

                                states[READER] = CODEX_STATE_RESTART;

                            } else if ((headers[READER] == CODEX_INDICATION_FAREND) && (indication == CODEX_INDICATION_NONE)) {

                                DIMINUTO_LOG_INFORMATION("%s: READ FAREND header=%d state=`%c` indication=%d\n", program, headers[READER], states[READER], indication);
                                states[READER] = CODEX_STATE_IDLE;
                                indication = CODEX_INDICATION_FAREND;
                                break;

                            } else if ((headers[READER] == CODEX_INDICATION_READY) && (indication == CODEX_INDICATION_NEAREND)) {

                                DIMINUTO_LOG_INFORMATION("%s: READ READY header=%d state=`%c` indication=%d\n", program, headers[READER], states[READER], indication);
                                states[READER] = CODEX_STATE_IDLE;
                                indication = CODEX_INDICATION_READY;
                                break;

                            } else {

                                states[READER] = CODEX_STATE_RESTART;

                            }

                        }

                    } while (codex_connection_is_ready(ssl));

                }

            } else if (fd == STDIN_FILENO) {

                if (states[WRITER] != CODEX_STATE_IDLE) {
                    /* Do nothing. */
                } else if (indication != CODEX_INDICATION_NONE) {
                    /* Do nothing. */
                } else {

                    bytes = diminuto_fd_read(STDIN_FILENO, buffers[WRITER], bufsize);
                    if (bytes <= 0) {
                        DIMINUTO_LOG_INFORMATION("%s: EOF fd=%d\n", program, STDIN_FILENO);
                        rc = diminuto_mux_unregister_read(&mux, STDIN_FILENO);
                        ASSERT(rc >= 0);
                        eof = true;
                        continue;
                    }

                    headers[WRITER] = bytes;

                    f16source = diminuto_fletcher_16(buffers[WRITER], headers[WRITER], &f16sourceA, &f16sourceB);
                    input += headers[WRITER];

                    states[WRITER] = verify ? CODEX_STATE_START : CODEX_STATE_RESTART;
                    verify = false;

                }

            } else {

                FATAL();

            }

        }

        if (states[READER] == CODEX_STATE_FINAL) {
            break;
        }

        if (states[READER] != CODEX_STATE_IDLE) {
            /* Do nothing. */
        } else if (states[WRITER] != CODEX_STATE_IDLE) {
            /* Do nothing. */
        } else if (indication == CODEX_INDICATION_READY) {

            DIMINUTO_LOG_INFORMATION("%s: NEAREND\n", program);

            /*
             * Renegotiation removed in Codex 11.0.0.
             */

            headers[WRITER] = CODEX_INDICATION_DONE;
            states[WRITER] = CODEX_STATE_RESTART;
            DIMINUTO_LOG_INFORMATION("%s: WRITE DONE header=%d state=`%c` indication=%d\n", program, headers[WRITER], states[WRITER], indication);
            do {
                states[WRITER] = codex_machine_writer(states[WRITER], expected, ssl, &(headers[WRITER]), buffers[WRITER], headers[WRITER], &(heres[WRITER]), &(lengths[WRITER]), &checked);
            } while ((states[WRITER] != CODEX_STATE_FINAL) && (states[WRITER] != CODEX_STATE_COMPLETE));
            if (states[WRITER] == CODEX_STATE_FINAL) {
                break;
            }

            states[READER] = CODEX_STATE_RESTART;
            states[WRITER] = CODEX_STATE_IDLE;
            verify = true;
            indication = CODEX_INDICATION_NONE;

        } else if (indication == CODEX_INDICATION_FAREND) {

            DIMINUTO_LOG_INFORMATION("%s: FAREND\n", program);

            /*
             * Drop into synchronous mode until the handshake is either complete
             * or fails.
             */

            headers[WRITER] = CODEX_INDICATION_READY;
            states[WRITER] = CODEX_STATE_RESTART;
            DIMINUTO_LOG_INFORMATION("%s: WRITE READY header=%d state=`%c` indication=%d\n", program, headers[WRITER], states[WRITER], indication);
            do {
                states[WRITER] = codex_machine_writer(states[WRITER], expected, ssl, &(headers[WRITER]), buffers[WRITER], headers[WRITER], &(heres[WRITER]), &(lengths[WRITER]), &checked);
            } while ((states[WRITER] != CODEX_STATE_FINAL) && (states[WRITER] != CODEX_STATE_COMPLETE));
            if (states[WRITER] == CODEX_STATE_FINAL) {
                break;
            }

            /*
             * Read until we get a DONE indication. The far end can write zero
             * length packets it it needs to drive the OpenSSL actions and our
             * reader machine will silently drop them. Likewise, we could write
             * zero length packets and the far end's reader state machine will
             * similarly silently drop them.
             */

            states[READER] = CODEX_STATE_RESTART;
            do {
                states[READER] = codex_machine_reader(states[READER], expected, ssl, &(headers[READER]), (void *)0, 0, &(heres[READER]), &(lengths[READER]), &checked);
            } while ((states[READER] != CODEX_STATE_FINAL) && (states[READER] != CODEX_STATE_COMPLETE));
            if (states[READER] == CODEX_STATE_FINAL) {
                break;
            }

            if (headers[READER] != CODEX_INDICATION_DONE) {
                break;
            }

            DIMINUTO_LOG_INFORMATION("%s: READ DONE header=%d state=`%c` indication=%d\n", program, headers[READER], states[READER], indication);

            states[READER] = CODEX_STATE_RESTART;
            states[WRITER] = CODEX_STATE_IDLE;
            verify = true;
            indication = CODEX_INDICATION_NONE;

        } else {
            FATAL(); /* Should never happen. */
        }

        diminuto_yield();

    }

    ticks = diminuto_timer_periodic(0);
    ASSERT(ticks >= 0);

    DIMINUTO_LOG_INFORMATION("%s: END eof=%d input=%llu output=%llu f16source=0x%4.4x f16sink=0x%4.4x\n", program, eof, ULL(input), ULL(output), f16sink, f16source);
    EXPECT(eof);
    EXPECT(input == output);
    EXPECT(f16source == f16sink);

    if (!eof) {
        rc = diminuto_mux_unregister_read(&mux, STDIN_FILENO);
        EXPECT(rc >= 0);
    }

    fd = codex_connection_descriptor(ssl);
    ASSERT(fd >= 0);

    rc = diminuto_mux_unregister_write(&mux, fd);
    EXPECT(rc >= 0);

    rc = diminuto_mux_unregister_read(&mux, fd);
    EXPECT(rc >= 0);

    diminuto_mux_fini(&mux);

    ssl = codex_connection_free(ssl);
    EXPECT(ssl == (codex_connection_t *)0);

    ctx = codex_context_free(ctx);
    EXPECT(ctx == (codex_context_t *)0);

    free(buffers[READER]);
    free(buffers[WRITER]);

    EXIT();
}

