/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 *
 * See the README.md for a list of references.
 */

/*******************************************************************************
 * HEADERS
 ******************************************************************************/

#define _GNU_SOURCE
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h> /* strcasecmp(3) */
#include <errno.h>
#include <stdio.h>
#include "com/diag/codex/codex.h"
#include "codex.h"

/*******************************************************************************
 * HELPERS
 ******************************************************************************/

static int codex_serialnumber_compare(diminuto_tree_t * thisp, diminuto_tree_t * thatp)
{
    return strcasecmp((const char *)(diminuto_store_downcast(thisp)->key), (const char *)(diminuto_store_downcast(thatp)->key));
}

/*******************************************************************************
 * REVOCATION
 ******************************************************************************/

char * codex_serialnumber_to_string(ASN1_INTEGER * srl, char * srn, size_t size)
{
	int ll = 0;
	int ii = 0;
	unsigned int dd = 0;

	if (size > 0) {
		ll = (size - 1) / 2;
		for (ii = 0; (ii < srl->length) && (ii < ll); ++ii) {
			dd = (srl->data[ii] & 0xf0) >> 4;
			srn[ii * 2] = (dd < 0xa) ? '0' + dd : 'A' + dd - 10;
			dd = (srl->data[ii] & 0x0f);
			srn[(ii * 2) + 1] = (dd < 0xa) ? '0' + dd : 'A' + dd - 10;
		}
		if (size > (ii * 2)) {
			srn[ii * 2] = '\0';
		}
	}

	return srn;
}

bool codex_serialnumber_is_revoked(const char * srn)
{
	diminuto_store_t * here = (diminuto_store_t *)0;
	diminuto_store_t that = DIMINUTO_STORE_KEYVALUEINIT(srn, (void *)0);

	here = diminuto_store_find(&codex_crl, &that, codex_serialnumber_compare);

	return (here != (diminuto_store_t *)0);
}
