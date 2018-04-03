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

#if defined(COM_DIAG_CODEX_PLATFORM_OPENSSL_1_1_0)

		/* Do nothing. */

#elif defined(COM_DIAG_CODEX_PLATFORM_OPENSSL_1_0_1)

		/* Do nothing. */

#elif defined(COM_DIAG_CODEX_PLATFORM_OPENSSL_1_0_2)

		DIMINUTO_LOG_INFORMATION("codex_handshake_renegotiate: OpenSSL 1.0.2\n");

		rc = SSL_renegotiate(ssl);
		if (rc != 1) {
			(void)codex_serror("SSL_renegotiate", ssl, rc);
			break;
		}

		codex_cerror();
		rc = SSL_do_handshake(ssl);
		if (rc != 1) {
			(void)codex_serror("SSL_do_handshake", ssl, rc);
			break;
		}

		if (!SSL_is_server(ssl)) {
			rc = 0;
			break;
		}

		ssl->state = SSL_ST_ACCEPT;

		codex_cerror();
		rc = SSL_do_handshake(ssl);
		if (rc != 1) {
			(void)codex_serror("SSL_do_handshake 2", ssl, rc);
			break;
		}

		rc = 0;
		break;

#elif defined(COM_DIAG_CODEX_PLATFORM_BORINGSSL)

		/* Do nothing. */

#elif defined(COM_DIAG_CODEX_PLATFORM_OPENSSL_1_1_1)

		/* Do nothing. */

#else

		/* Do nothing. */

#endif

		/* no break */

		DIMINUTO_LOG_NOTICE("codex_handshake_renegotiate: unsupported\n");
		break;

	} while (false);

	return rc;
}
