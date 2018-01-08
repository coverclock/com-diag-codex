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
		SSL_CTX * ctx;

		TEST();

		ctx = codex_client_new("etc/codex.crt", "etc/codex.pem");
		ASSERT(ctx != (SSL_CTX *)0);

		ctx = codex_client_free(ctx);
		ASSERT(ctx == (SSL_CTX *)0);

		STATUS();
	}

	EXIT();
}
