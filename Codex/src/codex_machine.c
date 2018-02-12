/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
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
#include <arpa/inet.h>
#include "com/diag/codex/codex.h"
#include "com/diag/diminuto/diminuto_log.h"
#include "com/diag/diminuto/diminuto_delay.h"
#include "codex.h"

/*******************************************************************************
 * MACHINES
 ******************************************************************************/

codex_state_t codex_machine_reader_generic(codex_state_t state, const char * expected, codex_connection_t * ssl, codex_header_t * header, void * buffer, int size, uint8_t ** here, int * length, codex_serror_t * serror)
{
	codex_state_t prior = state;
	int bytes = -1;

	DIMINUTO_LOG_DEBUG("codex_machine_reader_generic: BEGIN ssl=%p state='%c' expected=\"%s\" bytes=%d header=%d buffer=%p size=%d here=%p length=%d serror=%p\n", ssl, state, (expected == (const char *)0) ? "" : expected, bytes, *header, buffer, size, *here, *length, serror);

	switch (state) {

	case CODEX_STATE_START:

		if (codex_connection_is_server(ssl)) {
			/* Do nothing. */
		} else if (codex_connection_verify(ssl, expected) != CODEX_CONNECTION_VERIFY_FAILED) {
			/* Do nothing. */
		} else {
			DIMINUTO_LOG_NOTICE("codex_machine_reader_generic: UNEXPECTED ssl=%p\n", ssl);
			state = CODEX_STATE_FINAL;
			break;
		}

		/* no break */

	case CODEX_STATE_RESTART:

		*header = 0;
		*here = (uint8_t *)header;
		*length = sizeof(*header);

		/* no break */

	case CODEX_STATE_HEADER:

		bytes = codex_connection_read_generic(ssl, *here, *length, serror);
		if (bytes < 0) {
			state = (serror == (codex_serror_t *)0) ? CODEX_STATE_FINAL : CODEX_STATE_COMPLETE;
		} else if (bytes == 0) {
			state = CODEX_STATE_FINAL;
		} else if (bytes > *length) {
			DIMINUTO_LOG_ERROR("codex_machine_reader_generic: OVERFLOW ssl=%p bytes=%d length=%d\n", ssl, bytes, *length);
			state = CODEX_STATE_FINAL;
		} else {
			*here += bytes;
			*length -= bytes;
			*header = ntohl(*header);
			if (*length > 0) {
				state = CODEX_STATE_HEADER;
			} else if (*header < 0) {
				state = CODEX_STATE_COMPLETE;
			} else if (*header == 0) {
				state = CODEX_STATE_RESTART;
			} else if (*header > size) {
				DIMINUTO_LOG_WARNING("codex_machine_reader_generic: ENBIGGENED ssl=%p header=%d size=%d\n", ssl, *header, size);
				*here = (uint8_t *)buffer;
				*length = size;
				state = CODEX_STATE_PAYLOAD;
			} else {
				*here = (uint8_t *)buffer;
				*length = *header;
				state = CODEX_STATE_PAYLOAD;
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
			DIMINUTO_LOG_NOTICE("codex_machine_reader_generic: UNEXPECTED ssl=%p\n", ssl);
			state = CODEX_STATE_FINAL;
		}

		break;

	case CODEX_STATE_PAYLOAD:

		bytes = codex_connection_read_generic(ssl, *here, *length, serror);
		if (bytes < 0) {
			state = (serror == (codex_serror_t *)0) ? CODEX_STATE_FINAL : CODEX_STATE_COMPLETE;
		} else if (bytes == 0) {
			state = CODEX_STATE_FINAL;
		} else if (bytes > *length) {
			DIMINUTO_LOG_ERROR("codex_machine_reader_generic: OVERFLOW ssl=%p bytes=%d length=%d\n", ssl, bytes, *length);
			state = CODEX_STATE_FINAL;
		} else {
			*here += bytes;
			*length -= bytes;
			if (*length > 0) {
				state = CODEX_STATE_PAYLOAD;
			} else if (*header > size) {
				*length = *header - size;
				state = CODEX_STATE_SKIP;
			} else {
				state = CODEX_STATE_COMPLETE;
			}
		}

		break;

	case CODEX_STATE_SKIP:

		{
			char skip[512];
			int slack = sizeof(skip);

			if (*length < slack) {
				slack = *length;
			}
			bytes = codex_connection_read_generic(ssl, skip, slack, serror);
			if (bytes < 0) {
				state = (serror == (codex_serror_t *)0) ? CODEX_STATE_FINAL : CODEX_STATE_COMPLETE;
			} else if (bytes == 0) {
				state = CODEX_STATE_FINAL;
			} else if (bytes > slack) {
				DIMINUTO_LOG_ERROR("codex_machine_reader_generic: OVERFLOW ssl=%p bytes=%d slack=%d)\n", ssl, bytes, slack);
				state = CODEX_STATE_FINAL;
			} else {
				*length -= bytes;
				if (*length > 0) {
					state = CODEX_STATE_SKIP;
				} else {
					state = CODEX_STATE_COMPLETE;
				}
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

	if (prior == state) {
		/* Do nothing. */
	} else if (state != CODEX_STATE_FINAL) {
		/* Do nothing. */
	} else {
		(void)codex_connection_close(ssl);
	}

	DIMINUTO_LOG_DEBUG("codex_machine_reader_generic: END ssl=%p state='%c' expected=\"%s\" bytes=%d header=%d buffer=%p size=%d here=%p length=%d serror=%p\n", ssl, state, (expected == (const char *)0) ? "" : expected, bytes, *header, buffer, size, *here, *length, serror);

	return state;
}

codex_state_t codex_machine_writer_generic(codex_state_t state, const char * expected, codex_connection_t * ssl, codex_header_t * header, void * buffer, int size, uint8_t ** here, int * length, codex_serror_t * serror)
{
	codex_state_t prior = state;
	int bytes = -1;

	DIMINUTO_LOG_DEBUG("codex_machine_writer_generic: BEGIN ssl=%p state='%c' expected=\"%s\" bytes=%d header=%d buffer=%p size=%d here=%p length=%d serror=%p\n", ssl, state, (expected == (const char *)0) ? "" : expected, bytes, *header, buffer, size, *here, *length, serror);

	switch (state) {

	case CODEX_STATE_START:

		if (codex_connection_is_server(ssl)) {
			/* Do nothing. */
		} else if (codex_connection_verify(ssl, expected) != CODEX_CONNECTION_VERIFY_FAILED) {
			/* Do nothing. */
		} else {
			DIMINUTO_LOG_NOTICE("codex_machine_writer_generic: UNEXPECTED ssl=%p\n", ssl);
			state = CODEX_STATE_FINAL;
			break;
		}

		/* no break */

	case CODEX_STATE_RESTART:

		*header = htonl(size);
		*here = (uint8_t *)header;
		*length = sizeof(*header);

		/* no break */

	case CODEX_STATE_HEADER:

		bytes = codex_connection_write_generic(ssl, *here, *length, serror);
		if (bytes < 0) {
			state = (serror == (codex_serror_t *)0) ? CODEX_STATE_FINAL : CODEX_STATE_COMPLETE;
		} else if (bytes == 0) {
			state = CODEX_STATE_FINAL;
		} else if (bytes > *length) {
			DIMINUTO_LOG_ERROR("codex_machine_writer_generic: OVERFLOW ssl=%p bytes=%d length=%d\n", ssl, bytes, *length);
			state = CODEX_STATE_FINAL;
		} else {
			*here += bytes;
			*length -= bytes;
			*header = ntohl(*header);
			if (*length > 0) {
				state = CODEX_STATE_HEADER;
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
			DIMINUTO_LOG_NOTICE("codex_machine_writer_generic: UNEXPECTED ssl=%p\n", ssl);
			state = CODEX_STATE_FINAL;
		}

		break;

	case CODEX_STATE_PAYLOAD:

		bytes = codex_connection_write_generic(ssl, *here, *length, serror);
		if (bytes < 0) {
			state = (serror == (codex_serror_t *)0) ? CODEX_STATE_FINAL : CODEX_STATE_COMPLETE;
		} else if (bytes == 0) {
			state = CODEX_STATE_FINAL;
		} else if (bytes > *length) {
			DIMINUTO_LOG_ERROR("codex_machine_writer_generic: OVERFLOW ssl=%p bytes=%d length=%d\n", ssl, bytes, *length);
			state = CODEX_STATE_FINAL;
		} else {
			*here += bytes;
			*length -= bytes;
			if (*length > 0) {
				state = CODEX_STATE_PAYLOAD;
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

	if (prior == state) {
		/* Do nothing. */
	} else if (state != CODEX_STATE_FINAL) {
		/* Do nothing. */
	} else {
		(void)codex_connection_close(ssl);
	}

	DIMINUTO_LOG_DEBUG("codex_machine_writer_generic: END ssl=%p state='%c' expected=\"%s\" bytes=%d header=%d buffer=%p size=%d here=%p length=%d serror=%p\n", ssl, state, (expected == (const char *)0) ? "" : expected, bytes, *header, buffer, size, *here, *length, serror);

	return state;
}
