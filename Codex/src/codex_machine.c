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
#include "com/diag/diminuto/diminuto_log.h"
#include "com/diag/diminuto/diminuto_delay.h"
#include "codex.h"

/*******************************************************************************
 * MACHINES
 ******************************************************************************/

/*
 * The function call, codex_reader() or codex_writer(), is in effect the
 * stimulus passed into the state machines: the select(2) indicates we can
 * read or we can write.
 */

codex_state_t codex_machine_reader(codex_state_t state, codex_connection_t * ssl, codex_header_t * header, void * buffer, int size, uint8_t ** here, int * length)
{
	codex_state_t prior = CODEX_STATE_START;
	int bytes = -1;

	prior = state;
	switch (state) {

	case CODEX_STATE_START:
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
				state = CODEX_STATE_CONTROL;
			}
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
				state = CODEX_STATE_CONTROL;
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

	case CODEX_STATE_CONTROL:
		break;

	case CODEX_STATE_FINAL:
		break;

	}

	DIMINUTO_LOG_DEBUG("codex_machine_reader: prior=%c ssl=%p bytes=%d header=%d buffer=%p size=%d here=%p length=%d state=%c\n", prior, ssl, bytes, *header, buffer, size, *here, *length, state);

	return state;
}

codex_state_t codex_machine_writer(codex_state_t state, codex_connection_t * ssl, codex_header_t * header, void * buffer, int size, uint8_t ** here, int * length)
{
	codex_state_t prior = CODEX_STATE_START;
	int bytes = -1;

	prior = state;
	switch (state) {

	case CODEX_STATE_START:
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
				state = CODEX_STATE_CONTROL;
			}
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
				state = CODEX_STATE_CONTROL;
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

	case CODEX_STATE_CONTROL:
		break;

	case CODEX_STATE_FINAL:
		break;

	}

	DIMINUTO_LOG_DEBUG("codex_machine_writer: prior=%c ssl=%p bytes=%d header=%d buffer=%p size=%d here=%p length=%d state=%c\n", prior, ssl, bytes, *header, buffer, size, *here, *length, state);

	return state;
}
