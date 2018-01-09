/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in README.h<BR>
 * Chip Overclock (coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 */

#include "com/diag/diminuto/diminuto_unittest.h"
#include "com/diag/codex/codex.h"

int main(char * argc, char ** argv)
{

	{
		const char * value;

		TEST();

		value = getenv(COM_DIAG_CODEX_PASSWORD_ENV);
		COMMENT("%s=%s%s%s\n",
			COM_DIAG_CODEX_PASSWORD_ENV,
			(value != (const char *)0) ? "\"" : "",
			(value != (const char *)0) ? value : "(undefined)",
			(value != (const char *)0) ? "\"" : "");

		STATUS();
	}

	{
		SSL_CTX * ctx;

		TEST();

		ctx = codex_client_new("out/host/etc/client.pem", "out/host/etc/client.pem");
		EXPECT(ctx != (SSL_CTX *)0);

		ctx = codex_client_free(ctx);
		EXPECT(ctx == (SSL_CTX *)0);

		STATUS();
	}

	{
		SSL_CTX * ctx;

		TEST();

		ctx = codex_server_new("out/host/etc/server.pem", "out/host/etc/server.pem");
		EXPECT(ctx != (SSL_CTX *)0);

		ctx = codex_server_free(ctx);
		EXPECT(ctx == (SSL_CTX *)0);

		STATUS();
	}

	EXIT();
}
