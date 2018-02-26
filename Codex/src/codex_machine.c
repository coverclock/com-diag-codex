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

codex_state_t codex_machine_reader_generic(codex_state_t state, const char * expected, codex_connection_t * ssl, codex_header_t * header, void * buffer, size_t size, uint8_t ** here, size_t * length, codex_serror_t * serror)
{
	codex_state_t prior = state;
	ssize_t bytes = -1;
	int pending = -1;
	codex_serror_t error = CODEX_SERROR_IGNORE;

	pending = codex_connection_is_ready(ssl);

	DIMINUTO_LOG_DEBUG("codex_machine_reader_generic: begin ssl=%p state='%c' expected=%p bytes=%d header=0x%8.8x buffer=%p size=%u here=%p length=%u serror=%p pending=%d\n", ssl, state, expected, bytes, *header, buffer, size, *here, *length, serror, pending);

	switch (state) {

	case CODEX_STATE_START:

		/*
		 * Authenticate the server by traversing its certificate and verifying
		 * it via its common name (CN) or its fully qualified domain name
		 * (FQDN). The server certificate is available immediately upon the
		 * client's initial connection.
		 */

		if (codex_connection_is_server(ssl)) {
			/* Do nothing. */
		} else if (codex_connection_verify(ssl, expected) != CODEX_CONNECTION_VERIFY_FAILED) {
			/* Do nothing. */
		} else {
			DIMINUTO_LOG_NOTICE("codex_machine_reader_generic: unexpected role=server ssl=%p\n", ssl);
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

		bytes = codex_connection_read_generic(ssl, *here, *length, &error);
		if (bytes < 0) {
			if (serror != (codex_serror_t *)0) {
				*serror = error;
				state = CODEX_STATE_COMPLETE;
			} else if (error == CODEX_SERROR_WRITE) {
				/* Do nothing. */
			} else {
				state = CODEX_STATE_FINAL;
			}
		} else if (bytes == 0) {
			state = CODEX_STATE_FINAL;
		} else if (bytes > *length) {
			DIMINUTO_LOG_ERROR("codex_machine_reader_generic: overflow ssl=%p bytes=%d length=%u\n", ssl, bytes, *length);
			state = CODEX_STATE_FINAL;
		} else {
			*here += bytes;
			*length -= bytes;
			if (*length > 0) {
				state = CODEX_STATE_HEADER;
			} else {
				*header = ntohl(*header);
				if (*header < 0) {
					state = CODEX_STATE_COMPLETE;
				} else if (*header == 0) {
					state = CODEX_STATE_RESTART;
				} else if (*header > size) {
					DIMINUTO_LOG_WARNING("codex_machine_reader_generic: incompatible ssl=%p header=0x%8.8x size=%u\n", ssl, *header, size);
					*here = (uint8_t *)buffer;
					*length = size;
					state = CODEX_STATE_PAYLOAD;
				} else {
					*here = (uint8_t *)buffer;
					*length = *header;
					state = CODEX_STATE_PAYLOAD;
				}
			}
		}

		/*
		 * Authenticate the client by traversing its certificate and verifying
		 * it via its common name (CN) or its fully qualified domain name
		 * (FQDN). The client certificate is available only after the server has
		 * done its first I/O.
		 */

		if (!codex_connection_is_server(ssl)) {
			/* Do nothing. */
		} else if (prior != CODEX_STATE_START) {
			/* Do nothing. */
		} else if (state == CODEX_STATE_FINAL) {
			/* Do nothing. */
		} else if (codex_connection_verify(ssl, expected) != CODEX_CONNECTION_VERIFY_FAILED) {
			/* Do nothing. */
		} else {
			DIMINUTO_LOG_NOTICE("codex_machine_reader_generic: unexpected role=client ssl=%p\n", ssl);
			state = CODEX_STATE_FINAL;
		}

		break;

	case CODEX_STATE_PAYLOAD:

		bytes = codex_connection_read_generic(ssl, *here, *length, &error);
		if (bytes < 0) {
			if (serror != (codex_serror_t *)0) {
				*serror = error;
				state = CODEX_STATE_COMPLETE;
			} else if (error == CODEX_SERROR_WRITE) {
				/* Do nothing. */
			} else {
				state = CODEX_STATE_FINAL;
			}
		} else if (bytes == 0) {
			state = CODEX_STATE_FINAL;
		} else if (bytes > *length) {
			DIMINUTO_LOG_ERROR("codex_machine_reader_generic: overflow ssl=%p bytes=%d length=%u\n", ssl, bytes, *length);
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
			size_t slack = sizeof(skip);

			if (*length < slack) {
				slack = *length;
			}

			bytes = codex_connection_read_generic(ssl, skip, slack, &error);
			if (bytes < 0) {
				if (serror != (codex_serror_t *)0) {
					*serror = error;
					state = CODEX_STATE_COMPLETE;
				} else if (error == CODEX_SERROR_WRITE) {
					/* Do nothing. */
				} else {
					state = CODEX_STATE_FINAL;
				}
			} else if (bytes == 0) {
				state = CODEX_STATE_FINAL;
			} else if (bytes > slack) {
				DIMINUTO_LOG_ERROR("codex_machine_reader_generic: overflow ssl=%p bytes=%d slack=%u)\n", ssl, bytes, slack);
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
	case CODEX_STATE_IDLE:
	case CODEX_STATE_FINAL:
		break;

	}

	pending = codex_connection_is_ready(ssl);

	if (prior == state) {
		/* Do nothing. */
	} else if (state != CODEX_STATE_FINAL) {
		/* Do nothing. */
	} else {
		(void)codex_connection_close(ssl);
	}

	DIMINUTO_LOG_DEBUG("codex_machine_reader_generic: end ssl=%p state='%c' expected=%p bytes=%d header=0x%8.8x buffer=%p size=%u here=%p length=%u error=%c pending=%d\n", ssl, state, expected, bytes, *header, buffer, size, *here, *length, error, pending);

	return state;
}

codex_state_t codex_machine_writer_generic(codex_state_t state, const char * expected, codex_connection_t * ssl, codex_header_t * header, void * buffer, ssize_t size, uint8_t ** here, size_t * length, codex_serror_t * serror)
{
	codex_state_t prior = state;
	ssize_t bytes = -1;
	codex_serror_t error = CODEX_SERROR_IGNORE;

	DIMINUTO_LOG_DEBUG("codex_machine_writer_generic: begin ssl=%p state='%c' expected=%p bytes=%d header=0x%8.8x buffer=%p size=%d here=%p length=%u serror=%p\n", ssl, state, expected, bytes, *header, buffer, size, *here, *length, serror);

	switch (state) {

	case CODEX_STATE_START:

		/*
		 * Authenticate the server by traversing its certificate and verifying
		 * it via its common name (CN) or its fully qualified domain name
		 * (FQDN). The server certificate is available immediately upon the
		 * client's initial connection.
		 */

		if (codex_connection_is_server(ssl)) {
			/* Do nothing. */
		} else if (codex_connection_verify(ssl, expected) != CODEX_CONNECTION_VERIFY_FAILED) {
			/* Do nothing. */
		} else {
			DIMINUTO_LOG_NOTICE("codex_machine_writer_generic: unexpected role=server ssl=%p\n", ssl);
			state = CODEX_STATE_FINAL;
			break;
		}

		/* no break */

	case CODEX_STATE_RESTART:

		*header = size;
		*header = htonl(*header);
		*here = (uint8_t *)header;
		*length = sizeof(*header);

		/* no break */

	case CODEX_STATE_HEADER:

		bytes = codex_connection_write_generic(ssl, *here, *length, &error);
		if (bytes < 0) {
			if (serror != (codex_serror_t *)0) {
				*serror = error;
				state = CODEX_STATE_COMPLETE;
			} else if (error == CODEX_SERROR_READ) {
				/* Do nothing. */
			} else {
				state = CODEX_STATE_FINAL;
			}
		} else if (bytes == 0) {
			state = CODEX_STATE_FINAL;
		} else if (bytes > *length) {
			DIMINUTO_LOG_ERROR("codex_machine_writer_generic: overflow ssl=%p bytes=%d length=%u\n", ssl, bytes, *length);
			state = CODEX_STATE_FINAL;
		} else {
			*here += bytes;
			*length -= bytes;
			if (*length > 0) {
				state = CODEX_STATE_HEADER;
			} else if (size > 0) {
				*here = (uint8_t *)buffer;
				*length = size;
				state = CODEX_STATE_PAYLOAD;
			} else {
				/*
				 * It's either a zero length payload or a negative indication
				 * with no payload.
				 */
				state = CODEX_STATE_COMPLETE;
			}
		}

		/*
		 * Authenticate the client by traversing its certificate and verifying
		 * it via its common name (CN) or its fully qualified domain name
		 * (FQDN). The client certificate is available only after the server has
		 * done its first I/O.
		 */

		if (!codex_connection_is_server(ssl)) {
			/* Do nothing. */
		} else if (prior != CODEX_STATE_START) {
			/* Do nothing. */
		} else if (state == CODEX_STATE_FINAL) {
			/* Do nothing. */
		} else if (codex_connection_verify(ssl, expected) != CODEX_CONNECTION_VERIFY_FAILED) {
			/* Do nothing. */
		} else {
			DIMINUTO_LOG_NOTICE("codex_machine_writer_generic: unexpected role=client ssl=%p\n", ssl);
			state = CODEX_STATE_FINAL;
		}

		break;

	case CODEX_STATE_PAYLOAD:

		bytes = codex_connection_write_generic(ssl, *here, *length, &error);
		if (bytes < 0) {
			if (serror != (codex_serror_t *)0) {
				*serror = error;
				state = CODEX_STATE_COMPLETE;
			} else if (error == CODEX_SERROR_READ) {
				/* Do nothing. */
			} else {
				state = CODEX_STATE_FINAL;
			}
		} else if (bytes == 0) {
			state = CODEX_STATE_FINAL;
		} else if (bytes > *length) {
			DIMINUTO_LOG_ERROR("codex_machine_writer_generic: overflow ssl=%p bytes=%d length=%u\n", ssl, bytes, *length);
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
	case CODEX_STATE_IDLE:
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

	DIMINUTO_LOG_DEBUG("codex_machine_writer_generic: end ssl=%p state='%c' expected=%p bytes=%d header=0x8.8x buffer=%p size=%d here=%p length=%u error=%c\n", ssl, state, expected, bytes, *header, buffer, size, *here, *length, error);

	return state;
}
