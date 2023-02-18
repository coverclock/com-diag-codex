/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2018-2022 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 *
 * See the README.md for a list of references.
 */

/*******************************************************************************
 * HEADERS
 ******************************************************************************/

#include "com/diag/codex/codex.h"
#include "com/diag/diminuto/diminuto_criticalsection.h"
#include "com/diag/diminuto/diminuto_log.h"
#include "codex.h"

/*******************************************************************************
 * STATICS
 ******************************************************************************/

static pthread_mutex_t mutex_dh = PTHREAD_MUTEX_INITIALIZER;

/*******************************************************************************
 * DIFFIE-HELLMAN
 ******************************************************************************/

int codex_diffiehellman_import(const char * dhf)
{
    int rc = -1;
    BIO * bio = (BIO *)0;

    DIMINUTO_CRITICAL_SECTION_BEGIN(&mutex_dh);

        if (dhf == (const char *)0) {

            rc = 0;

        } else {

            DIMINUTO_LOG_DEBUG("codex_diffiehellman_import: dh dhf=\"%s\"\n", dhf);

            do {

                bio = BIO_new_file(dhf, "r");
                if (bio == (BIO *)0) {
                    codex_perror(dhf);
                    break;
                }

                rc = 0;

            } while (false);

            if (bio == (BIO *)0) {
                /* Do nothing. */
            } else if (BIO_free(bio) == 1) {
                /* Do nothing. */
            } else {
                codex_perror(dhf);
            }

        }

    DIMINUTO_CRITICAL_SECTION_END;

    return rc;
}
