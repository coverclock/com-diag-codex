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
#include "com/diag/diminuto/diminuto_core.h"
#include "com/diag/codex/codex.h"
#include "../src/codex.h"

int main(char * argc, char ** argv)
{

	(void)diminuto_core_enable();

	{
		const char * value;

		TEST();

		value = getenv(codex_server_password_env);
		COMMENT("%s=\"%s\"\n", codex_server_password_env, (value != (const char *)0) ? "(defined)" : "(UNDEFINED)");

		value = getenv(codex_client_password_env);
		COMMENT("%s=\"%s\"\n", codex_client_password_env, (value != (const char *)0) ? "(defined)" : "(UNDEFINED)");

		STATUS();
	}

	{
		int rc;

		TEST();

		rc = codex_initialize();
		ASSERT(rc == 0);

		STATUS();
	}
	{
		int rc;

		TEST();

		ASSERT(codex_dh512 == (DH *)0);
		ASSERT(codex_dh1024 == (DH *)0);
		ASSERT(codex_dh2048 == (DH *)0);
		ASSERT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, NULL, NULL, NULL);
		ASSERT(rc == 0);

		ASSERT(codex_dh512 == (DH *)0);
		ASSERT(codex_dh1024 == (DH *)0);
		ASSERT(codex_dh2048 == (DH *)0);
		ASSERT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(COM_DIAG_CODEX_OUT_ETC_PATH "/dh0.pem", NULL, NULL, NULL);
		ASSERT(rc < 0);

		ASSERT(codex_dh512 == (DH *)0);
		ASSERT(codex_dh1024 == (DH *)0);
		ASSERT(codex_dh2048 == (DH *)0);
		ASSERT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, COM_DIAG_CODEX_OUT_ETC_PATH "/dh0.pem", NULL, NULL);
		ASSERT(rc < 0);

		ASSERT(codex_dh512 == (DH *)0);
		ASSERT(codex_dh1024 == (DH *)0);
		ASSERT(codex_dh2048 == (DH *)0);
		ASSERT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, NULL, COM_DIAG_CODEX_OUT_ETC_PATH "/dh0.pem", NULL);
		ASSERT(rc < 0);

		ASSERT(codex_dh512 == (DH *)0);
		ASSERT(codex_dh1024 == (DH *)0);
		ASSERT(codex_dh2048 == (DH *)0);
		ASSERT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, NULL, NULL, COM_DIAG_CODEX_OUT_ETC_PATH "/dh0.pem");
		ASSERT(rc < 0);

		ASSERT(codex_dh512 == (DH *)0);
		ASSERT(codex_dh1024 == (DH *)0);
		ASSERT(codex_dh2048 == (DH *)0);
		ASSERT(codex_dh4096 == (DH *)0);

		rc = codex_parameters("/dev/null", NULL, NULL, NULL);
		ASSERT(rc < 0);

		ASSERT(codex_dh512 == (DH *)0);
		ASSERT(codex_dh1024 == (DH *)0);
		ASSERT(codex_dh2048 == (DH *)0);
		ASSERT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, "/dev/null", NULL, NULL);
		ASSERT(rc < 0);

		ASSERT(codex_dh512 == (DH *)0);
		ASSERT(codex_dh1024 == (DH *)0);
		ASSERT(codex_dh2048 == (DH *)0);
		ASSERT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, NULL, "/dev/null", NULL);
		ASSERT(rc < 0);

		ASSERT(codex_dh512 == (DH *)0);
		ASSERT(codex_dh1024 == (DH *)0);
		ASSERT(codex_dh2048 == (DH *)0);
		ASSERT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, NULL, NULL, "/dev/null");
		ASSERT(rc < 0);

		ASSERT(codex_dh512 == (DH *)0);
		ASSERT(codex_dh1024 == (DH *)0);
		ASSERT(codex_dh2048 == (DH *)0);
		ASSERT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(COM_DIAG_CODEX_OUT_ETC_PATH "/dh4294967295.pem", NULL, NULL, NULL);
		ASSERT(rc < 0);

		ASSERT(codex_dh512 == (DH *)0);
		ASSERT(codex_dh1024 == (DH *)0);
		ASSERT(codex_dh2048 == (DH *)0);
		ASSERT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, COM_DIAG_CODEX_OUT_ETC_PATH "/dh4294967295.pem", NULL, NULL);
		ASSERT(rc < 0);

		ASSERT(codex_dh512 == (DH *)0);
		ASSERT(codex_dh1024 == (DH *)0);
		ASSERT(codex_dh2048 == (DH *)0);
		ASSERT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, NULL, COM_DIAG_CODEX_OUT_ETC_PATH "/dh4294967295.pem", NULL);
		ASSERT(rc < 0);

		ASSERT(codex_dh512 == (DH *)0);
		ASSERT(codex_dh1024 == (DH *)0);
		ASSERT(codex_dh2048 == (DH *)0);
		ASSERT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, NULL, NULL, COM_DIAG_CODEX_OUT_ETC_PATH "/dh4294967295.pem");
		ASSERT(rc < 0);

		ASSERT(codex_dh512 == (DH *)0);
		ASSERT(codex_dh1024 == (DH *)0);
		ASSERT(codex_dh2048 == (DH *)0);
		ASSERT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(COM_DIAG_CODEX_OUT_ETC_PATH "/dh512.pem", NULL, NULL, NULL);
		ASSERT(rc == 0);

		ASSERT(codex_dh512 != (DH *)0);
		ASSERT(codex_dh1024 == (DH *)0);
		ASSERT(codex_dh2048 == (DH *)0);
		ASSERT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, COM_DIAG_CODEX_OUT_ETC_PATH "/dh1024.pem", NULL, NULL);
		ASSERT(rc == 0);

		ASSERT(codex_dh512 != (DH *)0);
		ASSERT(codex_dh1024 != (DH *)0);
		ASSERT(codex_dh2048 == (DH *)0);
		ASSERT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, NULL, COM_DIAG_CODEX_OUT_ETC_PATH "/dh2048.pem", NULL);
		ASSERT(rc == 0);

		ASSERT(codex_dh512 != (DH *)0);
		ASSERT(codex_dh1024 != (DH *)0);
		ASSERT(codex_dh2048 != (DH *)0);
		ASSERT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, NULL, NULL, COM_DIAG_CODEX_OUT_ETC_PATH "/dh4096.pem");
		ASSERT(rc == 0);

		ASSERT(codex_dh512 != (DH *)0);
		ASSERT(codex_dh1024 != (DH *)0);
		ASSERT(codex_dh2048 != (DH *)0);
		ASSERT(codex_dh4096 != (DH *)0);

		/*
		 * Probable memory leak here to set up for the following unit test.
		 */

		codex_dh512 = (DH *)0;
		codex_dh1024 = (DH *)0;
		codex_dh2048 = (DH *)0;
		codex_dh4096 = (DH *)0;

		STATUS();
	}

	{
		int rc;

		TEST();

		ASSERT(codex_dh512 == (DH *)0);
		ASSERT(codex_dh1024 == (DH *)0);
		ASSERT(codex_dh2048 == (DH *)0);
		ASSERT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(COM_DIAG_CODEX_OUT_ETC_PATH "/dh512.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh1024.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh2048.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh4096.pem");
		ASSERT(rc == 0);

		ASSERT(codex_dh512 != (DH *)0);
		ASSERT(codex_dh1024 != (DH *)0);
		ASSERT(codex_dh2048 != (DH *)0);
		ASSERT(codex_dh4096 != (DH *)0);

		STATUS();
	}


	{
		SSL_CTX * ctx;

		TEST();

		ctx = codex_client_new(COM_DIAG_CODEX_OUT_ETC_PATH "/root.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/client.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/client.pem");
		EXPECT(ctx != (SSL_CTX *)0);

		ctx = codex_client_free(ctx);
		EXPECT(ctx == (SSL_CTX *)0);

		STATUS();
	}

	{
		SSL_CTX * ctx;

		TEST();

		ctx = codex_server_new(COM_DIAG_CODEX_OUT_ETC_PATH "/root.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/server.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/server.pem");
		EXPECT(ctx != (SSL_CTX *)0);

		ctx = codex_server_free(ctx);
		EXPECT(ctx == (SSL_CTX *)0);

		STATUS();
	}

	EXIT();
}
