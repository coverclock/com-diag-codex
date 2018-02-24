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

#if defined(COM_DIAG_CODEX_PLATFORM_OPENSSL_1_0_1)

		/* Do nothing. */

#elif defined(COM_DIAG_CODEX_PLATFORM_OPENSSL_1_0_2)

		DIMINUTO_LOG_INFORMATION("codex_handshake_renegotiate: OpenSSL 1.0.2\n");

		rc = SSL_renegotiate(ssl);
		if (rc != 1) {
			(void)codex_serror("SSL_renegotiate", ssl, rc);
			rc = -1;
			break;
		}

		codex_cerror();
		rc = SSL_do_handshake(ssl);
		if (rc != 1) {
			(void)codex_serror("SSL_do_handshake", ssl, rc);
			rc = -1;
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
			rc = -1;
			break;
		}

		rc = 0;
		break;

#elif defined(COM_DIAG_CODEX_PLATFORM_BORINGSSL) && 0

		DIMINUTO_LOG_NOTICE("codex_handshake_renegotiate: BoringSSL 1.1.0\n");

		rc = SSL_renegotiate(ssl);
		if (rc != 1) {
			(void)codex_serror("SSL_renegotiate", ssl, rc);
			rc = -1;
			break;
		}

		codex_cerror();
		rc = SSL_do_handshake(ssl);
		if (rc != 1) {
			(void)codex_serror("SSL_do_handshake", ssl, rc);
			rc = -1;
			break;
		}

		if (!SSL_is_server(ssl)) {
			rc = 0;
			break;
		}

		SSL_set_accept_state(ssl);

		codex_cerror();
		rc = SSL_do_handshake(ssl);
		if (rc != 1) {
			(void)codex_serror("SSL_do_handshake 2", ssl, rc);
			rc = -1;
			break;
		}

		rc = 0;
		break;

#elif defined(COM_DIAG_CODEX_PLATFORM_OPENSSL_1_1_1) && 0

		DIMINUTO_LOG_INFORMATION("codex_handshake_renegotiate: OpenSSL 1.1.1\n");

		rc = SSL_renegotiate(ssl);
		if (rc != 1) {
			(void)codex_serror("SSL_renegotiate", ssl, rc);
			rc = -1;
			break;
		}

		if (SSL_is_server((codex_connection_t *)ssl)) {
			SSL_set_accept_state(ssl);
		} else {
			SSL_set_connect_state(ssl);
		}

		codex_cerror();
		rc = SSL_do_handshake(ssl);
		if (rc != 1) {
			(void)codex_serror("SSL_do_handshake", ssl, rc);
			rc = -1;
			break;
		}

		if (!SSL_is_server(ssl)) {
			rc = 0;
			break;
		}

		codex_cerror();
		rc = SSL_do_handshake(ssl);
		if (rc != 1) {
			(void)codex_serror("SSL_do_handshake 2", ssl, rc);
			rc = -1;
			break;
		}

		rc = 0;
		break;

#else

		/* Do nothing. */

#endif

		DIMINUTO_LOG_NOTICE("codex_handshake_renegotiate: unsupported\n");
		break;

	} while (false);

	return rc;
}
