/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 *
 * Codex Machine a.k.a. Layer 2.
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
#include "com/diag/diminuto/diminuto_criticalsection.h"
#include "com/diag/diminuto/diminuto_log.h"
#include "com/diag/diminuto/diminuto_delay.h"
#include "com/diag/diminuto/diminuto_token.h"
#include "codex.h"

/*******************************************************************************
 * MACHINES
 ******************************************************************************/

/*
 * The function call, codex_reader() or codex_writer(), is in effect the
 * stimulus passed into the state machines: we want to read, or we want to
 * write.
 */

codex_state_t codex_reader(codex_state_t state, codex_connection_t * ssl, codex_header_t * header, void * buffer, int size, uint8_t ** here, int * length)
{
	int bytes = -1;

	switch (state) {

	case CODEX_STATE_START:
	case CODEX_STATE_COMPLETE:
		*here = (uint8_t *)header;
		*length = sizeof(*header);
		bytes = codex_connection_read(ssl, *here, *length);
		if (bytes < 0) {
			state = CODEX_STATE_ERROR;
		} else if (bytes == 0) {
			state = CODEX_STATE_CLOSED;
		} else if (bytes > *length) {
			state = CODEX_STATE_ERROR;
		} else {
			*here += bytes;
			*length -= bytes;
			if (*length > 0) {
				state = CODEX_STATE_HEADER;
			} else if (*header > size) {
				state = CODEX_STATE_ERROR;
			} else if (*header > 0) {
				*here = (uint8_t *)buffer;
				*length = *header;
				state = CODEX_STATE_PAYLOAD;
			} else {
				state = CODEX_STATE_CONTROL;
			}
		}
		break;

	case CODEX_STATE_HEADER:
		bytes = codex_connection_read(ssl, *here, *length);
		if (bytes < 0) {
			state = CODEX_STATE_ERROR;
		} else if (bytes == 0) {
			state = CODEX_STATE_CLOSED;
		} else if (bytes > *length) {
			state = CODEX_STATE_ERROR;
		} else {
			*here += bytes;
			*length -= bytes;
			if (*length > 0) {
				/* Do nothing. */
			} else if (*header > size) {
				state = CODEX_STATE_ERROR;
			} else if (*header > 0) {
				*here = (uint8_t *)buffer;
				*length = *header;
				state = CODEX_STATE_PAYLOAD;
			} else {
				state = CODEX_STATE_CONTROL;
			}
		}
		break;

	case CODEX_STATE_PAYLOAD:
		bytes = codex_connection_read(ssl, *here, *length);
		if (bytes < 0) {
			state = CODEX_STATE_ERROR;
		} else if (bytes == 0) {
			state = CODEX_STATE_CLOSED;
		} else if (bytes > *length) {
			state = CODEX_STATE_ERROR;
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

	case CODEX_STATE_CONTROL:
		break;

	case CODEX_STATE_ERROR:
		break;

	case CODEX_STATE_CLOSED:
		break;

	}

	return state;
}

codex_state_t codex_writer(codex_state_t state, codex_connection_t * ssl, codex_header_t * header, const void * buffer, int size, const uint8_t ** here, int * length)
{
	int bytes = -1;

	switch (state) {

	case CODEX_STATE_START:
	case CODEX_STATE_COMPLETE:
		*header = size;
		*here = (uint8_t *)header;
		*length = sizeof(*header);
		bytes = codex_connection_write(ssl, *here, *length);
		if (bytes < 0) {
			state = CODEX_STATE_ERROR;
		} else if (bytes == 0) {
			state = CODEX_STATE_CLOSED;
		} else if (bytes > *length) {
			state = CODEX_STATE_ERROR;
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
				state = CODEX_STATE_CONTROL;
			}
		}
		break;

	case CODEX_STATE_HEADER:
		bytes = codex_connection_write(ssl, *here, *length);
		if (bytes < 0) {
			state = CODEX_STATE_ERROR;
		} else if (bytes == 0) {
			state = CODEX_STATE_CLOSED;
		} else if (bytes > *length) {
			state = CODEX_STATE_ERROR;
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
				state = CODEX_STATE_CONTROL;
			}
		}
		break;

	case CODEX_STATE_PAYLOAD:
		bytes = codex_connection_write(ssl, *here, *length);
		if (bytes < 0) {
			state = CODEX_STATE_ERROR;
		} else if (bytes == 0) {
			state = CODEX_STATE_CLOSED;
		} else if (bytes > *length) {
			state = CODEX_STATE_ERROR;
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

	case CODEX_STATE_CONTROL:
		break;

	case CODEX_STATE_ERROR:
		break;

	case CODEX_STATE_CLOSED:
		break;

	}

	return state;
}
