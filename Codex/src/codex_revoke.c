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

#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strcasecmp(3) */
#include <errno.h>
#include "com/diag/codex/codex.h"
#include "com/diag/diminuto/diminuto_criticalsection.h"
#include "com/diag/diminuto/diminuto_log.h"
#include "com/diag/diminuto/diminuto_tree.h"
#include "codex.h"

/*******************************************************************************
 * STATICS
 ******************************************************************************/

static pthread_mutex_t mutex_crl = PTHREAD_MUTEX_INITIALIZER;

static diminuto_tree_t * codex_crl = DIMINUTO_TREE_EMPTY;

/*******************************************************************************
 * CALLBACKS
 ******************************************************************************/

static int codex_serialnumber_compare(diminuto_tree_t * here, diminuto_tree_t * there)
{
    return strcasecmp((const char *)(here->data), (const char *)(there->data));
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
	bool result = false;
	int rc = 0;
	diminuto_tree_t * here = (diminuto_tree_t *)0;
	diminuto_tree_t that = DIMINUTO_TREE_DATAINIT((void *)srn);

	DIMINUTO_CRITICAL_SECTION_BEGIN(&mutex_crl);

		here = diminuto_tree_search(codex_crl, &that, codex_serialnumber_compare, &rc);
		if (here == (diminuto_tree_t *)0) {
			/* Do nothing. */
		} else if (rc != 0) {
			/* Do nothing. */
		} else {
			result = true;
			DIMINUTO_LOG_INFORMATION("codex_serialnumber_is_revoked: crl SRL=%s\n", (const char *)(here->data));
		}

	DIMINUTO_CRITICAL_SECTION_END;

	return result;
}

int codex_revoked_import_stream(FILE * fp)
{
	int rc = 0;
	int nn = 0;
	char * srn = (char *)0;
	diminuto_tree_t * here = (diminuto_tree_t *)0;
	diminuto_tree_t * there = (diminuto_tree_t *)0;

	while (true) {

		nn = fscanf(fp, " %20m[0123456789abcdefABCDEF]%*[^\n]\n", &srn);
		if (nn == EOF) {
			break;
		} else if (nn != 1) {
			continue;
		} else {
			/* Do nothing. */
		}

		here = (diminuto_tree_t *)malloc(sizeof(diminuto_tree_t));
		if (here == (diminuto_tree_t *)0) {
			diminuto_perror("malloc");
			break;
		}

		DIMINUTO_CRITICAL_SECTION_BEGIN(&mutex_crl);

			there = diminuto_tree_search_insert_or_replace(&codex_crl, diminuto_tree_datainit(here, srn), codex_serialnumber_compare, !0);

		DIMINUTO_CRITICAL_SECTION_END;

		if (there != (diminuto_tree_t *)0) {
			free(here->data);
			free(here);
		}

		DIMINUTO_LOG_DEBUG("codex_revoked_import_stream: crl SRL=%s\n", srn);

		rc += 1;

	}

	return rc;
}

int codex_revoked_import(const char * crl)
{
	int rc = -1;
	FILE * fp = (FILE *)0;

	do {

		if (crl == (const char *)0) {
			rc = 0; /* Not an error. */
			break;
		}

		fp = fopen(crl, "r");
		if (fp == (FILE *)0) {
			diminuto_perror(crl);
			break;
		}

		DIMINUTO_LOG_DEBUG("codex_revoked_import: crl=\"%s\"\n", crl);

		rc = codex_revoked_import_stream(fp);

		if (fclose(fp) == EOF) {
			diminuto_perror(crl);
		}

	} while (0);

	return rc;
}
