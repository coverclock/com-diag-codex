/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2018-2023 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 *
 * See the README.md for a list of references.
 *
 * This module was written under the assumption that the SSL socket
 * is being multiplexed (see the Mux feature) for *both* reads and
 * writes. It tries not to block unnecessarily on SSL reads.
 */

/*******************************************************************************
 * HEADERS
 ******************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <arpa/inet.h>
#if !defined(_BSD_SOURCE)
#define _BSD_SOURCE
#endif
#include <endian.h>
#include "com/diag/codex/codex.h"
#include "com/diag/diminuto/diminuto_delay.h"
#include "com/diag/diminuto/diminuto_log.h"
#include "codex.h"

/*******************************************************************************
 * HELPERS
 ******************************************************************************/

/*
 * It figures I'd pick a type, int32_t, that on some platforms is equivalent
 * to neither a long nor a short. Note that network byte order is Big Endian.
 */

static inline codex_header_t ntoh32(codex_header_t header)
{
    return be32toh(header);
}

static inline codex_header_t hton32(codex_header_t header)
{
    return htobe32(header);
}

/*******************************************************************************
 * MACHINES
 ******************************************************************************/

codex_state_t codex_machine_reader_generic(codex_state_t state, const char * expected, codex_connection_t * ssl, codex_header_t * header, void * buffer, size_t size, uint8_t ** here, size_t * length, bool * checked, codex_serror_t * serror, int * mask)
{
    int verification = ~0;
    ssize_t bytes = -1;
    codex_serror_t error = CODEX_SERROR_SUCCESS;
    bool repeat = false;

    do {

        repeat = false;

        DIMINUTO_LOG_DEBUG("codex_machine_reader_generic: begin ssl=%p state='%c' expected=%p bytes=%zd header=0x%8.8x buffer=%p size=%zu here=%p length=%zu checked=%d serror=%p mask=%p repeat=%d\n", ssl, state, (expected == (const char *)0) ? "" : expected, bytes, *header, buffer, size, *here, *length, *checked, serror, mask, repeat);
    
        switch (state) {
    
        case CODEX_STATE_START:
    
            /*
             * Authenticate the farend by traversing its certificate and verifying
             * it via its common name (CN) or its fully qualified domain name
             * (FQDN). The server certificate is available immediately upon the
             * client's initial connection. This also means that there may not be
             * any more data in the pipeline to be read and a subsequent read will
             * block, indefinitely in the case that the far end isn't sending.
             */
    
            if (codex_connection_is_server(ssl)) {
                /* Do nothing. */
            } else if (*checked) {
                /* Do nothing. */
            } else {
                *checked = true;
                verification = codex_connection_verify(ssl, expected);
                if (mask != (int *)0) {
                    *mask = verification;
                }
                if (!codex_connection_verified(verification)) {
                    DIMINUTO_LOG_NOTICE("codex_machine_reader_generic: unexpected farend=server ssl=%p\n", ssl);
                    state = CODEX_STATE_FINAL;
                } else {
                    DIMINUTO_LOG_INFORMATION("codex_machine_reader_generic: verified farend=server ssl=%p\n", ssl);
                    state = CODEX_STATE_RESTART;
                }
            }
            if (state != CODEX_STATE_FINAL) {
                state = CODEX_STATE_RESTART;
                repeat = true;
            }
            break;
    
        case CODEX_STATE_RESTART:
    
            *header = 0;
            *here = (uint8_t *)header;
            *length = sizeof(*header);
            state = CODEX_STATE_HEADER;
            repeat = codex_connection_is_ready(ssl);
            break;
    
        case CODEX_STATE_HEADER:
    
            bytes = codex_connection_read_generic(ssl, *here, *length, &error);
            if (bytes < 0) {
    
                /*
                 * The SSL stack piggybacks all its own read and write needs for
                 * its own protocol on the application reads and writes. So it's
                 * possible that the stack needs to write (read) for its own needs
                 * before it can service the application read (write). The Codex
                 * state machines handle this by [1] passing this information back
                 * to the application if the application asked for it in the API by
                 * providing a pointer to a variable in which this information is
                 * stored, [2] ignoring it and remaining in the same state in the
                 * hopes the application will do the requisite read or write as
                 * part of its normal behavior. (Option [3] is if the read or write
                 * failed for some other reason, the state machine just makes the
                 * state as FINAL and shuts down the connection.
                 */
    
                if (serror != (codex_serror_t *)0) {
                    *serror = error;
                }
                if (error != CODEX_SERROR_WRITE) {
                    state = CODEX_STATE_FINAL;
                } else if (serror == (codex_serror_t *)0) {
                    DIMINUTO_LOG_NOTICE("codex_machine_reader: writeful ssl=%p\n", ssl);
                    diminuto_yield();
                } else {
                    /* Do nothing. */
                }
    
            } else if (bytes == 0) {
    
                state = CODEX_STATE_FINAL;
    
            } else if (bytes > *length) {
    
                DIMINUTO_LOG_ERROR("codex_machine_reader_generic: overflow ssl=%p bytes=%zd length=%zu\n", ssl, bytes, *length);
                state = CODEX_STATE_FINAL;
    
            } else {
    
                /*
                 * Authenticate the farend by traversing its certificate and
                 * verifying it via its common name (CN) or its fully qualified
                 * domain name (FQDN). The client certificate is available only
                 * after the nearend has successfully completed its first read.
                 */
        
                if (!codex_connection_is_server(ssl)) {
                    /* Do nothing. */
                } else if (bytes <= 0) {
                    /* Do nothing. */
                } else if (*checked) {
                    /* Do nothing. */
                } else {
                    *checked = true;
                    verification = codex_connection_verify(ssl, expected);
                    if (mask != (int *)0) {
                        *mask = verification;
                    }
                    if (!codex_connection_verified(verification)) {
                        DIMINUTO_LOG_NOTICE("codex_machine_reader_generic: unexpected farend=client ssl=%p\n", ssl);
                        state = CODEX_STATE_FINAL;
                    } else {
                        DIMINUTO_LOG_INFORMATION("codex_machine_reader_generic: verified farend=client ssl=%p\n", ssl);
                    }
                }
                if (state != CODEX_STATE_FINAL) { 
                    *here += bytes;
                    *length -= bytes;
                    if (*length == 0) {
                        *header = ntoh32(*header);
                        if (*header < 0) {
                            /*
                             * This is an indication with no payload.
                             */
                            state = CODEX_STATE_COMPLETE;
                        } else if (*header == 0) {
                            /*
                             * A zero length segment is not only legitimate, but
                             * sometimes necessary to accomodate the SSL stack.
                             * We ignore it.
                             */
                            state = CODEX_STATE_RESTART;
                            repeat = codex_connection_is_ready(ssl);
                        } else if (*header > size) {
                            DIMINUTO_LOG_WARNING("codex_machine_reader_generic: incompatible ssl=%p header=0x%8.8x size=%zu\n", ssl, *header, size);
                            state = CODEX_STATE_FINAL;
                        } else {
                            *here = (uint8_t *)buffer;
                            *length = *header;
                            state = CODEX_STATE_PAYLOAD;
                            repeat = codex_connection_is_ready(ssl);
                        }
                    }
                }
            }
            break;
    
        case CODEX_STATE_PAYLOAD:
   
            bytes = codex_connection_read_generic(ssl, *here, *length, &error);
            if (bytes < 0) {
    
                /*
                 * (Same comments as above regarding SSL needing to write in
                 * order to read, or read in order to write.)
                 */
    
                if (serror != (codex_serror_t *)0) {
                    *serror = error;
                }
                if (error != CODEX_SERROR_WRITE) {
                    state = CODEX_STATE_FINAL;
                } else if (serror == (codex_serror_t *)0) {
                    DIMINUTO_LOG_NOTICE("codex_machine_reader: writeful ssl=%p\n", ssl);
                    diminuto_yield();
                } else {
                    /* Do nothing. */
                }
        
            } else if (bytes == 0) {
    
                state = CODEX_STATE_FINAL;
    
            } else if (bytes > *length) {
    
                DIMINUTO_LOG_ERROR("codex_machine_reader_generic: overflow ssl=%p bytes=%zd length=%zu\n", ssl, bytes, *length);
                state = CODEX_STATE_FINAL;
    
            } else {
    
                *here += bytes;
                *length -= bytes;
                if (*length == 0) {
                    state = CODEX_STATE_COMPLETE;
                } else {
                    repeat = codex_connection_is_ready(ssl);
                }
    
            }
            break;
    
        case CODEX_STATE_COMPLETE:
        case CODEX_STATE_IDLE:
        case CODEX_STATE_FINAL:
            break;
    
        }
    
        DIMINUTO_LOG_DEBUG("codex_machine_reader_generic: end ssl=%p state='%c' expected=%p bytes=%zd header=0x%8.8x buffer=%p size=%zu here=%p length=%zu checked=%d error='%c' repeat=%d\n", ssl, state, (expected == (const char *)0) ? "" : expected, bytes, *header, buffer, size, *here, *length, *checked, error, repeat);

    } while (repeat);

    return state;
}

codex_state_t codex_machine_writer_generic(codex_state_t state, const char * expected, codex_connection_t * ssl, codex_header_t * header, void * buffer, ssize_t size, uint8_t ** here, size_t * length, bool * checked, codex_serror_t * serror, int * mask)
{
    int verification = ~0;
    ssize_t bytes = -1;
    codex_serror_t error = CODEX_SERROR_SUCCESS;
    bool repeat = false;

    do {

        repeat = false;

        DIMINUTO_LOG_DEBUG("codex_machine_writer_generic: begin ssl=%p state='%c' expected=%p bytes=%zd header=0x%8.8x buffer=%p size=%zu here=%p length=%zu checked=%d serror=%p\n", ssl, state, (expected == (const char *)0) ? "" : expected, bytes, *header, buffer, size, *here, *length, *checked, serror);
    
        switch (state) {
    
        case CODEX_STATE_START:
    
            /*
             * Authenticate the server by traversing its certificate and verifying
             * it via its common name (CN) or its fully qualified domain name
             * (FQDN). The server certificate is available immediately upon the
             * client's initial connection.
             */
    
            if (!codex_connection_is_server(ssl)) {
                *checked = true;
                verification = codex_connection_verify(ssl, expected);
                if (mask != (int *)0) {
                    *mask = verification;
                }
                if (!codex_connection_verified(verification)) {
                    DIMINUTO_LOG_NOTICE("codex_machine_writer_generic: unexpected farend=server ssl=%p\n", ssl);
                    state = CODEX_STATE_FINAL;
                } else {
                    DIMINUTO_LOG_INFORMATION("codex_machine_writer_generic: verified farend=server ssl=%p\n", ssl);
                }
            }
            state = CODEX_STATE_RESTART;
            repeat = true;
            break;
    
        case CODEX_STATE_RESTART:
    
            *header = size;
            *header = hton32(*header);
            *here = (uint8_t *)header;
            *length = sizeof(*header);
            state = CODEX_STATE_HEADER;
            repeat = true;
            break;
    
        case CODEX_STATE_HEADER:
    
            bytes = codex_connection_write_generic(ssl, *here, *length, &error);
            if (bytes < 0) {
    
                /*
                 * The SSL stack piggybacks all its own read and write needs for
                 * its own protocol on the application reads and writes. So it's
                 * possible that the stack needs to write (read) for its own needs
                 * before it can service the application read (write). The Codex
                 * state machines handle this by [1] passing this information back
                 * to the application if the application asked for it in the API by
                 * providing a pointer to a variable in which this information is
                 * stored, [2] ignoring it and remaining in the same state in the
                 * hopes the application will do the requisite read or write as
                 * part of its normal behavior. (Option [3] is if the read or write
                 * failed for some other reason, the state machine just makes the
                 * state as FINAL and shuts down the connection.
                 */
    
                if (serror != (codex_serror_t *)0) {
                    *serror = error;
                }
                if (error != CODEX_SERROR_READ) {
                    state = CODEX_STATE_FINAL;
                } else if (serror == (codex_serror_t *)0) {
                    DIMINUTO_LOG_NOTICE("codex_machine_writer: read ssl=%p\n", ssl);
                    diminuto_yield();
                } else {
                    /* Do nothing. */
                }
    
            } else if (bytes == 0) {
    
                state = CODEX_STATE_FINAL;
    
            } else if (bytes > *length) {
    
                DIMINUTO_LOG_ERROR("codex_machine_writer_generic: overflow ssl=%p bytes=%zd length=%zu\n", ssl, bytes, *length);
                state = CODEX_STATE_FINAL;
    
            } else {
    
                *here += bytes;
                *length -= bytes;
                if (*length > 0) {
                    /* Do nothing. */
                } else if (size > 0) {
                    *here = (uint8_t *)buffer;
                    *length = size;
                    state = CODEX_STATE_PAYLOAD;
                } else {
                    state = CODEX_STATE_COMPLETE;
                }
    
            }
            break;
    
        case CODEX_STATE_PAYLOAD:
    
            bytes = codex_connection_write_generic(ssl, *here, *length, &error);
            if (bytes < 0) {
    
                /*
                 * (Same comments as above regarding SSL needing to write in
                 * order to read, or read in order to write.)
                 */
    
                if (serror != (codex_serror_t *)0) {
                    *serror = error;
                }
                if (error != CODEX_SERROR_READ) {
                    state = CODEX_STATE_FINAL;
                } else if (serror == (codex_serror_t *)0) {
                    DIMINUTO_LOG_NOTICE("codex_machine_writer: readful ssl=%p\n", ssl);
                    diminuto_yield();
                } else {
                    /* Do nothing. */
                }
    
            } else if (bytes == 0) {
    
                state = CODEX_STATE_FINAL;
    
            } else if (bytes > *length) {
    
                DIMINUTO_LOG_ERROR("codex_machine_writer_generic: overflow ssl=%p bytes=%zd length=%zu\n", ssl, bytes, *length);
                state = CODEX_STATE_FINAL;
    
            } else {
    
                *here += bytes;
                *length -= bytes;
                if (*length == 0) {
                    state = CODEX_STATE_COMPLETE;
                }
    
            }
            break;
    
        case CODEX_STATE_COMPLETE:
        case CODEX_STATE_IDLE:
        case CODEX_STATE_FINAL:
            break;
    
        }
    
        DIMINUTO_LOG_DEBUG("codex_machine_writer_generic: end ssl=%p state='%c' expected=%p bytes=%zd header=0x%8.8x buffer=%p size=%zu here=%p length=%zu checked=%d error='%c'\n", ssl, state, (expected == (const char *)0) ? "" : expected, bytes, *header, buffer, size, *here, *length, *checked, error);

    } while (repeat);

    return state;
}
