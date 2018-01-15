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
#include "com/diag/diminuto/diminuto_log.h"
#include "com/diag/diminuto/diminuto_core.h"
#include "com/diag/codex/codex.h"
#include "../src/codex_unittest.h"
#include "../src/codex.h"

int main(char * argc, char ** argv)
{

	(void)diminuto_core_enable();

	diminuto_log_setmask();

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
		EXPECT(rc == 0);

		STATUS();
	}


	{
		int rc;
		DH * temp_dh256;
		DH * temp_dh512;
		DH * temp_dh1024;
		DH * temp_dh2048;
		DH * temp_dh4096;

		TEST();

		EXPECT(codex_dh256 == (DH *)0);
		EXPECT(codex_dh512 == (DH *)0);
		EXPECT(codex_dh1024 == (DH *)0);
		EXPECT(codex_dh2048 == (DH *)0);
		EXPECT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, NULL, NULL, NULL, NULL);
		EXPECT(rc == 0);

		EXPECT(codex_dh256 == (DH *)0);
		EXPECT(codex_dh512 == (DH *)0);
		EXPECT(codex_dh1024 == (DH *)0);
		EXPECT(codex_dh2048 == (DH *)0);
		EXPECT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(COM_DIAG_CODEX_OUT_ETC_PATH "/dh0.pem", NULL, NULL, NULL, NULL);
		EXPECT(rc < 0);

		EXPECT(codex_dh256 == (DH *)0);
		EXPECT(codex_dh512 == (DH *)0);
		EXPECT(codex_dh1024 == (DH *)0);
		EXPECT(codex_dh2048 == (DH *)0);
		EXPECT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, COM_DIAG_CODEX_OUT_ETC_PATH "/dh0.pem", NULL, NULL, NULL);
		EXPECT(rc < 0);

		EXPECT(codex_dh256 == (DH *)0);
		EXPECT(codex_dh512 == (DH *)0);
		EXPECT(codex_dh1024 == (DH *)0);
		EXPECT(codex_dh2048 == (DH *)0);
		EXPECT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, NULL, COM_DIAG_CODEX_OUT_ETC_PATH "/dh0.pem", NULL, NULL);
		EXPECT(rc < 0);

		EXPECT(codex_dh256 == (DH *)0);
		EXPECT(codex_dh512 == (DH *)0);
		EXPECT(codex_dh1024 == (DH *)0);
		EXPECT(codex_dh2048 == (DH *)0);
		EXPECT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, NULL, NULL, COM_DIAG_CODEX_OUT_ETC_PATH "/dh0.pem", NULL);
		EXPECT(rc < 0);

		EXPECT(codex_dh256 == (DH *)0);
		EXPECT(codex_dh512 == (DH *)0);
		EXPECT(codex_dh1024 == (DH *)0);
		EXPECT(codex_dh2048 == (DH *)0);
		EXPECT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, NULL, NULL, NULL, COM_DIAG_CODEX_OUT_ETC_PATH "/dh0.pem");
		EXPECT(rc < 0);

		EXPECT(codex_dh256 == (DH *)0);
		EXPECT(codex_dh512 == (DH *)0);
		EXPECT(codex_dh1024 == (DH *)0);
		EXPECT(codex_dh2048 == (DH *)0);
		EXPECT(codex_dh4096 == (DH *)0);

		rc = codex_parameters("/dev/null", NULL, NULL, NULL, NULL);
		EXPECT(rc < 0);

		EXPECT(codex_dh256 == (DH *)0);
		EXPECT(codex_dh512 == (DH *)0);
		EXPECT(codex_dh1024 == (DH *)0);
		EXPECT(codex_dh2048 == (DH *)0);
		EXPECT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, "/dev/null", NULL, NULL, NULL);
		EXPECT(rc < 0);

		EXPECT(codex_dh256 == (DH *)0);
		EXPECT(codex_dh512 == (DH *)0);
		EXPECT(codex_dh1024 == (DH *)0);
		EXPECT(codex_dh2048 == (DH *)0);
		EXPECT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, NULL, "/dev/null", NULL, NULL);
		EXPECT(rc < 0);

		EXPECT(codex_dh256 == (DH *)0);
		EXPECT(codex_dh512 == (DH *)0);
		EXPECT(codex_dh1024 == (DH *)0);
		EXPECT(codex_dh2048 == (DH *)0);
		EXPECT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, NULL, NULL, "/dev/null", NULL);
		EXPECT(rc < 0);

		EXPECT(codex_dh256 == (DH *)0);
		EXPECT(codex_dh512 == (DH *)0);
		EXPECT(codex_dh1024 == (DH *)0);
		EXPECT(codex_dh2048 == (DH *)0);
		EXPECT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, NULL, NULL, NULL, "/dev/null");
		EXPECT(rc < 0);

		EXPECT(codex_dh256 == (DH *)0);
		EXPECT(codex_dh512 == (DH *)0);
		EXPECT(codex_dh1024 == (DH *)0);
		EXPECT(codex_dh2048 == (DH *)0);
		EXPECT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(COM_DIAG_CODEX_OUT_ETC_PATH "/dh4294967295.pem", NULL, NULL, NULL, NULL);
		EXPECT(rc < 0);

		EXPECT(codex_dh256 == (DH *)0);
		EXPECT(codex_dh512 == (DH *)0);
		EXPECT(codex_dh1024 == (DH *)0);
		EXPECT(codex_dh2048 == (DH *)0);
		EXPECT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, COM_DIAG_CODEX_OUT_ETC_PATH "/dh4294967295.pem", NULL, NULL, NULL);
		EXPECT(rc < 0);

		EXPECT(codex_dh256 == (DH *)0);
		EXPECT(codex_dh512 == (DH *)0);
		EXPECT(codex_dh1024 == (DH *)0);
		EXPECT(codex_dh2048 == (DH *)0);
		EXPECT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, NULL, COM_DIAG_CODEX_OUT_ETC_PATH "/dh4294967295.pem", NULL, NULL);
		EXPECT(rc < 0);

		EXPECT(codex_dh256 == (DH *)0);
		EXPECT(codex_dh512 == (DH *)0);
		EXPECT(codex_dh1024 == (DH *)0);
		EXPECT(codex_dh2048 == (DH *)0);
		EXPECT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, NULL, NULL, COM_DIAG_CODEX_OUT_ETC_PATH "/dh4294967295.pem", NULL);
		EXPECT(rc < 0);

		EXPECT(codex_dh256 == (DH *)0);
		EXPECT(codex_dh512 == (DH *)0);
		EXPECT(codex_dh1024 == (DH *)0);
		EXPECT(codex_dh2048 == (DH *)0);
		EXPECT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, NULL, NULL, NULL, COM_DIAG_CODEX_OUT_ETC_PATH "/dh4294967295.pem");
		EXPECT(rc < 0);

		EXPECT(codex_dh256 == (DH *)0);
		EXPECT(codex_dh512 == (DH *)0);
		EXPECT(codex_dh1024 == (DH *)0);
		EXPECT(codex_dh2048 == (DH *)0);
		EXPECT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(COM_DIAG_CODEX_OUT_ETC_PATH "/dh256.pem", NULL, NULL, NULL, NULL);
		EXPECT(rc == 0);

		EXPECT(codex_dh256 != (DH *)0);
		EXPECT(codex_dh512 == (DH *)0);
		EXPECT(codex_dh1024 == (DH *)0);
		EXPECT(codex_dh2048 == (DH *)0);
		EXPECT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, COM_DIAG_CODEX_OUT_ETC_PATH "/dh512.pem", NULL, NULL, NULL);
		EXPECT(rc == 0);

		EXPECT(codex_dh256 != (DH *)0);
		EXPECT(codex_dh512 != (DH *)0);
		EXPECT(codex_dh1024 == (DH *)0);
		EXPECT(codex_dh2048 == (DH *)0);
		EXPECT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, NULL, COM_DIAG_CODEX_OUT_ETC_PATH "/dh1024.pem", NULL, NULL);
		EXPECT(rc == 0);

		EXPECT(codex_dh256 != (DH *)0);
		EXPECT(codex_dh512 != (DH *)0);
		EXPECT(codex_dh1024 != (DH *)0);
		EXPECT(codex_dh2048 == (DH *)0);
		EXPECT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, NULL, NULL, COM_DIAG_CODEX_OUT_ETC_PATH "/dh2048.pem", NULL);
		EXPECT(rc == 0);

		EXPECT(codex_dh256 != (DH *)0);
		EXPECT(codex_dh512 != (DH *)0);
		EXPECT(codex_dh1024 != (DH *)0);
		EXPECT(codex_dh2048 != (DH *)0);
		EXPECT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(NULL, NULL, NULL, NULL, COM_DIAG_CODEX_OUT_ETC_PATH "/dh4096.pem");
		EXPECT(rc == 0);

		EXPECT(codex_dh256 != (DH *)0);
		EXPECT(codex_dh512 != (DH *)0);
		EXPECT(codex_dh1024 != (DH *)0);
		EXPECT(codex_dh2048 != (DH *)0);
		EXPECT(codex_dh4096 != (DH *)0);

		temp_dh256 = codex_dh256;
		temp_dh512 = codex_dh512;
		temp_dh1024 = codex_dh1024;
		temp_dh2048 = codex_dh2048;
		temp_dh4096 = codex_dh4096;

		rc = codex_parameters(COM_DIAG_CODEX_OUT_ETC_PATH "/dh256.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh512.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh1024.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh2048.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh4096.pem");
		EXPECT(rc == 0);

		EXPECT(codex_dh256 == temp_dh256);
		EXPECT(codex_dh512 == temp_dh512);
		EXPECT(codex_dh1024 == temp_dh1024);
		EXPECT(codex_dh2048 == temp_dh2048);
		EXPECT(codex_dh4096 == temp_dh4096);

		/*
		 * Probable memory leak here to set up for the following unit test.
		 */

		codex_dh256 = (DH *)0;
		codex_dh512 = (DH *)0;
		codex_dh1024 = (DH *)0;
		codex_dh2048 = (DH *)0;
		codex_dh4096 = (DH *)0;

		EXPECT(codex_dh256 == (DH *)0);
		EXPECT(codex_dh512 == (DH *)0);
		EXPECT(codex_dh1024 == (DH *)0);
		EXPECT(codex_dh2048 == (DH *)0);
		EXPECT(codex_dh4096 == (DH *)0);

		rc = codex_parameters(COM_DIAG_CODEX_OUT_ETC_PATH "/dh256.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh512.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh1024.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh2048.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/dh4096.pem");
		EXPECT(rc == 0);

		EXPECT(codex_dh256 != (DH *)0);
		EXPECT(codex_dh512 != (DH *)0);
		EXPECT(codex_dh1024 != (DH *)0);
		EXPECT(codex_dh2048 != (DH *)0);
		EXPECT(codex_dh4096 != (DH *)0);

		STATUS();
	}

	{
		DH * dh;
		int exp;

		TEST();

		for (exp = 0; exp <= 1; ++exp) {

			EXPECT(codex_dh256 != (DH *)0);
			dh = codex_parameters_callback((SSL *)0, exp, 256);
			EXPECT(dh == codex_dh256);

			EXPECT(codex_dh512 != (DH *)0);
			dh = codex_parameters_callback((SSL *)0, exp, 512);
			EXPECT(dh == codex_dh512);

			EXPECT(codex_dh1024 != (DH *)0);
			dh = codex_parameters_callback((SSL *)0, exp, 1024);
			EXPECT(dh == codex_dh1024);

			EXPECT(codex_dh2048 != (DH *)0);
			dh = codex_parameters_callback((SSL *)0, exp, 2048);
			EXPECT(dh == codex_dh2048);

			EXPECT(codex_dh4096 != (DH *)0);
			dh = codex_parameters_callback((SSL *)0, exp, 4096);
			EXPECT(dh == codex_dh4096);

			dh = codex_parameters_callback((SSL *)0, exp, 8192);
			EXPECT(dh == (DH *)0);

		}

		STATUS();
	}

	{
		char buffer[sizeof("PASSWORD")];
		int writing;
		int len;

		TEST();

		for (writing = 0; writing <= 1; ++writing) {

			strncpy(buffer, "DEADBEEF", sizeof(buffer));
			len = codex_password_callback((void *)0, sizeof(buffer), writing, "PASSWORD");
			EXPECT(len == 0);
			EXPECT(strcmp(buffer, "DEADBEEF") == 0);

			strncpy(buffer, "DEADBEEF", sizeof(buffer));
			len = codex_password_callback(buffer, sizeof(buffer), writing, (void *)0);
			EXPECT(len == 0);
			EXPECT(strcmp(buffer, "") == 0);

			strncpy(buffer, "DEADBEEF", sizeof(buffer));
			len = codex_password_callback(buffer, 0, writing, (void *)"PASSWORD");
			EXPECT(len == 0);
			EXPECT(strcmp(buffer, "DEADBEEF") == 0);

			strncpy(buffer, "DEADBEEF", sizeof(buffer));
			len = codex_password_callback(buffer, 1, writing, (void *)"PASSWORD");
			EXPECT(len == 0);
			EXPECT(strcmp(buffer, "") == 0);

			strncpy(buffer, "DEADBEEF", sizeof(buffer));
			len = codex_password_callback(buffer, 5, writing, (void *)"PASSWORD");
			EXPECT(len == 0);
			EXPECT(strcmp(buffer, "") == 0);

			strncpy(buffer, "DEADBEEF", sizeof(buffer));
			len = codex_password_callback(buffer, sizeof(buffer), writing, (void *)"PASSWORD");
			EXPECT(len == strlen("PASSWORD"));
			EXPECT(strcmp(buffer, "PASSWORD") == 0);
		}

		STATUS();
	}

	{
		codex_context_t * ctx;

		TEST();

		ctx = codex_client_context_new(COM_DIAG_CODEX_OUT_ETC_PATH "/root.pem", COM_DIAG_CODEX_OUT_ETC_PATH, COM_DIAG_CODEX_OUT_ETC_PATH "/client.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/client.pem");
		ASSERT(ctx != (codex_context_t *)0);

		ctx = codex_context_free(ctx);
		EXPECT(ctx == (codex_context_t *)0);

		STATUS();
	}

	{
		codex_context_t * ctx;

		TEST();

		ctx = codex_server_context_new(COM_DIAG_CODEX_OUT_ETC_PATH "/root.pem", COM_DIAG_CODEX_OUT_ETC_PATH, COM_DIAG_CODEX_OUT_ETC_PATH "/server.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/server.pem");
		ASSERT(ctx != (codex_context_t *)0);

		ctx = codex_context_free(ctx);
		EXPECT(ctx == (codex_context_t *)0);

		STATUS();
	}

	{
		codex_context_t * ctx;
		codex_rendezvous_t * acc;

		TEST();

		ctx = codex_server_context_new(COM_DIAG_CODEX_OUT_ETC_PATH "/root.pem", COM_DIAG_CODEX_OUT_ETC_PATH, COM_DIAG_CODEX_OUT_ETC_PATH "/server.pem", COM_DIAG_CODEX_OUT_ETC_PATH "/server.pem");
		ASSERT(ctx != (codex_context_t *)0);

		acc = codex_server_rendezvous_new("0");
		ASSERT(acc != (codex_rendezvous_t *)0);

		acc = codex_server_rendezvous_free(acc);
		EXPECT(acc == (codex_rendezvous_t *)0);

		ctx = codex_context_free(ctx);
		EXPECT(ctx == (codex_context_t *)0);

		STATUS();
	}

	EXIT();
}
