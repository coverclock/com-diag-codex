/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 *
 * MACHINE
 *
 * See the README.md for a list of references.
 */

/*******************************************************************************
 * HEADERS
 ******************************************************************************/

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include "com/diag/codex/codex.h"
#include "com/diag/diminuto/diminuto_log.h"
#include "com/diag/diminuto/diminuto_delay.h"
#include "codex.h"

/*******************************************************************************
 * MACHINES
 ******************************************************************************/

codex_state_t codex_machine_reader(codex_state_t state, const char * expected, codex_connection_t * ssl, codex_header_t * header, void * buffer, int size, uint8_t ** here, int * length)
{
	codex_state_t prior = state;
	int bytes = -1;

	switch (state) {

	case CODEX_STATE_START:

		if (codex_connection_is_server(ssl)) {
			/* Do nothing. */
		} else if (codex_connection_verify(ssl, expected) != CODEX_CONNECTION_VERIFY_FAILED) {
			/* Do nothing. */
		} else {
			state = CODEX_STATE_FINAL;
			break;
		}

		/* no break */

	case CODEX_STATE_RESTART:

		*header = 0;
		*here = (uint8_t *)header;
		*length = sizeof(*header);
		bytes = codex_connection_read(ssl, *here, *length);
		if (bytes < 0) {
			state = CODEX_STATE_FINAL;
		} else if (bytes == 0) {
			state = CODEX_STATE_FINAL;
		} else if (bytes > *length) {
			state = CODEX_STATE_FINAL;
		} else {
			*here += bytes;
			*length -= bytes;
			if (*length > 0) {
				state = CODEX_STATE_HEADER;
			} else if (*header > size) {
				state = CODEX_STATE_FINAL;
			} else if (*header > 0) {
				*here = (uint8_t *)buffer;
				*length = *header;
				state = CODEX_STATE_PAYLOAD;
			} else {
				state = CODEX_STATE_COMPLETE;
			}
		}

		if (!codex_connection_is_server(ssl)) {
			/* Do nothing. */
		} else if (prior != CODEX_STATE_START) {
			/* Do nothing. */
		} else if (state == CODEX_STATE_FINAL) {
			/* Do nothing. */
		} else if (codex_connection_verify(ssl, expected) != CODEX_CONNECTION_VERIFY_FAILED) {
			/* Do nothing. */
		} else {
			state = CODEX_STATE_FINAL;
			break;
		}

		break;

	case CODEX_STATE_HEADER:

		bytes = codex_connection_read(ssl, *here, *length);
		if (bytes < 0) {
			state = CODEX_STATE_FINAL;
		} else if (bytes == 0) {
			state = CODEX_STATE_FINAL;
		} else if (bytes > *length) {
			state = CODEX_STATE_FINAL;
		} else {
			*here += bytes;
			*length -= bytes;
			if (*length > 0) {
				/* Do nothing. */
			} else if (*header > size) {
				state = CODEX_STATE_FINAL;
			} else if (*header > 0) {
				*here = (uint8_t *)buffer;
				*length = *header;
				state = CODEX_STATE_PAYLOAD;
			} else {
				state = CODEX_STATE_COMPLETE;
			}
		}

		break;

	case CODEX_STATE_PAYLOAD:

		bytes = codex_connection_read(ssl, *here, *length);
		if (bytes < 0) {
			state = CODEX_STATE_FINAL;
		} else if (bytes == 0) {
			state = CODEX_STATE_FINAL;
		} else if (bytes > *length) {
			state = CODEX_STATE_FINAL;
		} else {
			*here += bytes;
			*length -= bytes;
			if (*length > 0) {
				/* Do nothing. */
			} else {
				state = CODEX_STATE_COMPLETE;
			}
		}

		break;

	case CODEX_STATE_COMPLETE:

		break;

	case CODEX_STATE_IDLE:

		break;

	case CODEX_STATE_FINAL:

		break;

	}

	DIMINUTO_LOG_DEBUG("codex_machine_reader: prior=%c ssl=%p expected=\"%s\" bytes=%d header=%d buffer=%p size=%d here=%p length=%d state=%c\n", prior, ssl, (expected == (const char *)0) ? "" : expected, bytes, *header, buffer, size, *here, *length, state);

	return state;
}

codex_state_t codex_machine_writer(codex_state_t state, const char * expected, codex_connection_t * ssl, codex_header_t * header, void * buffer, int size, uint8_t ** here, int * length)
{
	codex_state_t prior = state;
	int bytes = -1;

	switch (state) {

	case CODEX_STATE_START:

		if (codex_connection_is_server(ssl)) {
			/* Do nothing. */
		} else if (codex_connection_verify(ssl, expected) != CODEX_CONNECTION_VERIFY_FAILED) {
			/* Do nothing. */
		} else {
			state = CODEX_STATE_FINAL;
			break;
		}

		/* no break */

	case CODEX_STATE_RESTART:

		*header = size;
		*here = (uint8_t *)header;
		*length = sizeof(*header);
		bytes = codex_connection_write(ssl, *here, *length);
		if (bytes < 0) {
			state = CODEX_STATE_FINAL;
		} else if (bytes == 0) {
			state = CODEX_STATE_FINAL;
		} else if (bytes > *length) {
			state = CODEX_STATE_FINAL;
		} else {
			*here += bytes;
			*length -= bytes;
			if (*length > 0) {
				state = CODEX_STATE_HEADER;
			} else if (*header > 0) {
				*here = (uint8_t *)buffer;
				*length = size;
				state = CODEX_STATE_PAYLOAD;
			} else {
				state = CODEX_STATE_COMPLETE;
			}
		}

		if (!codex_connection_is_server(ssl)) {
			/* Do nothing. */
		} else if (prior != CODEX_STATE_START) {
			/* Do nothing. */
		} else if (state == CODEX_STATE_FINAL) {
			/* Do nothing. */
		} else if (codex_connection_verify(ssl, expected) != CODEX_CONNECTION_VERIFY_FAILED) {
			/* Do nothing. */
		} else {
			state = CODEX_STATE_FINAL;
			break;
		}

		break;

	case CODEX_STATE_HEADER:

		bytes = codex_connection_write(ssl, *here, *length);
		if (bytes < 0) {
			state = CODEX_STATE_FINAL;
		} else if (bytes == 0) {
			state = CODEX_STATE_FINAL;
		} else if (bytes > *length) {
			state = CODEX_STATE_FINAL;
		} else {
			*here += bytes;
			*length -= bytes;
			if (*length > 0) {
				/* Do nothing. */
			} else if (*header > 0) {
				*here = (uint8_t *)buffer;
				*length = size;
				state = CODEX_STATE_PAYLOAD;
			} else {
				state = CODEX_STATE_COMPLETE;
			}
		}

		break;

	case CODEX_STATE_PAYLOAD:

		bytes = codex_connection_write(ssl, *here, *length);
		if (bytes < 0) {
			state = CODEX_STATE_FINAL;
		} else if (bytes == 0) {
			state = CODEX_STATE_FINAL;
		} else if (bytes > *length) {
			state = CODEX_STATE_FINAL;
		} else {
			*here += bytes;
			*length -= bytes;
			if (*length > 0) {
				/* Do nothing. */
			} else {
				state = CODEX_STATE_COMPLETE;
			}
		}

		break;

	case CODEX_STATE_COMPLETE:

		break;

	case CODEX_STATE_IDLE:

		break;

	case CODEX_STATE_FINAL:

		break;

	}

	DIMINUTO_LOG_DEBUG("codex_machine_writer: prior=%c ssl=%p expected=\"%s\" bytes=%d header=%d buffer=%p size=%d here=%p length=%d state=%c\n", prior, ssl, (expected == (const char *)0) ? "" : expected, bytes, *header, buffer, size, *here, *length, state);

	return state;
}
