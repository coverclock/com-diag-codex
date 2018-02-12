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
#include "../src/codex.h"
#include "unittest-core.h"
#include <string.h>

int main(char * argc, char ** argv)
{

	(void)diminuto_core_enable();

	diminuto_log_setmask();

	{
		TEST();

		ASSERT(codex_method != (char *)0);
		COMMENT("codex_method=(%s)\n", codex_method);
		EXPECT(*codex_method != '\0');

		COMMENT("codex_certificate_depth=%d\n", codex_certificate_depth);
		EXPECT(codex_certificate_depth > 0);

		ASSERT(codex_cipher_list != (char *)0);
		COMMENT("codex_cipher_list=\"%s\"\n", codex_cipher_list);
		EXPECT(*codex_cipher_list != '\0');

		ASSERT(codex_session_id_context != (char *)0);
		COMMENT("codex_session_id_context=\"%s\"\n", codex_session_id_context);
		EXPECT(*codex_session_id_context != '\0');

		COMMENT("codex_renegotiate_bytes=%ld\n", codex_renegotiate_bytes);
		EXPECT(codex_renegotiate_bytes > 0);

		COMMENT("codex_renegotiate_seconds=%ld\n", codex_renegotiate_seconds);
		EXPECT(codex_renegotiate_seconds > 0);


		STATUS();
	}

	{
		const char * value;

		TEST();

		ASSERT(codex_server_password_env != (char *)0);
		EXPECT(*codex_server_password_env != '\0');
		value = getenv(codex_server_password_env);
		ASSERT(value != (const char *)0);
		ADVISE(*value != '\0');
		COMMENT("%s=\"%s\"\n", codex_server_password_env, (value != (const char *)0) ? "(defined)" : "(UNDEFINED)");

		ASSERT(codex_client_password_env != (char *)0);
		EXPECT(*codex_client_password_env != '\0');
		value = getenv(codex_client_password_env);
		ASSERT(value != (const char *)0);
		ADVISE(*value != '\0');
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
		DH * dh;

		TEST();

		EXPECT(codex_dh == (DH *)0);
		rc = codex_parameters(COM_DIAG_CODEX_OUT_CRT_PATH "/" "dh.pem");
		EXPECT(rc == 0);
		EXPECT(codex_dh != (DH *)0);
		dh = codex_dh;
		rc = codex_parameters(COM_DIAG_CODEX_OUT_CRT_PATH "/" "dh.pem");
		EXPECT(rc == 0);
		EXPECT(codex_dh == dh);

	}

	{
		DH * dh;
		int exp;
		int key;

		TEST();

		EXPECT(codex_dh != (DH *)0);

		for (exp = 0; exp <= 1; ++exp) {
			for (key = 256; key <= 2048; key *= 2) {

				dh = codex_parameters_callback((SSL *)0, exp, key);
				EXPECT(dh == codex_dh);

			}

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

		ctx = codex_client_context_new(COM_DIAG_CODEX_OUT_CRT_PATH "/root.pem", COM_DIAG_CODEX_OUT_CRT_PATH, COM_DIAG_CODEX_OUT_CRT_PATH "/client.pem", COM_DIAG_CODEX_OUT_CRT_PATH "/client.pem");
		ASSERT(ctx != (codex_context_t *)0);

		ctx = codex_context_free(ctx);
		EXPECT(ctx == (codex_context_t *)0);

		STATUS();
	}

	{
		codex_context_t * ctx;

		TEST();

		ctx = codex_server_context_new(COM_DIAG_CODEX_OUT_CRT_PATH "/root.pem", COM_DIAG_CODEX_OUT_CRT_PATH, COM_DIAG_CODEX_OUT_CRT_PATH "/server.pem", COM_DIAG_CODEX_OUT_CRT_PATH "/server.pem");
		ASSERT(ctx != (codex_context_t *)0);

		ctx = codex_context_free(ctx);
		EXPECT(ctx == (codex_context_t *)0);

		STATUS();
	}

	{
		codex_context_t * ctx;
		codex_rendezvous_t * acc;

		TEST();

		ctx = codex_server_context_new(COM_DIAG_CODEX_OUT_CRT_PATH "/root.pem", COM_DIAG_CODEX_OUT_CRT_PATH, COM_DIAG_CODEX_OUT_CRT_PATH "/server.pem", COM_DIAG_CODEX_OUT_CRT_PATH "/server.pem");
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
