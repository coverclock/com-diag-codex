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

#include "com/diag/codex/codex.h"
#include "com/diag/diminuto/diminuto_log.h"
#include "codex.h"

/*******************************************************************************
 * HANDSHAKE
 ******************************************************************************/

int codex_handshake_renegotiate(codex_connection_t * ssl)
{
	int rc = -1;

	do {

#if defined(COM_DIAG_CODEX_PLATFORM_BORINGSSL)
		if (!SSL_is_server(ssl)) {
			DIMINUTO_LOG_ERROR("codex_handshake_renegotiate: unsupported\n");
			rc = -1;
			break;
		}
#endif

		rc = SSL_renegotiate(ssl);
		if (rc != 1) {
			(void)codex_serror("SSL_renegotiate", ssl, rc);
			rc = -1;
			break;
		}

		rc = SSL_do_handshake(ssl);
		if (rc != 1) {
			(void)codex_serror("SSL_do_handshake", ssl, rc);
			rc = -1;
			break;
		}

#if !defined(COM_DIAG_CODEX_PLATFORM_BORINGSSL)
		if (!SSL_is_server(ssl)) {
			rc = 0;
			break;
		}

		ssl->state = SSL_ST_ACCEPT;
#endif

		rc = SSL_do_handshake(ssl);
		if (rc != 1) {
			(void)codex_serror("SSL_do_handshake 2", ssl, rc);
			rc = -1;
			break;
		}

		rc = 0;

	} while (false);

	return rc;
}
