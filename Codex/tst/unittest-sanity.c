/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in README.h<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 */

#include "com/diag/diminuto/diminuto_unittest.h"
#include "com/diag/diminuto/diminuto_log.h"
#include "com/diag/diminuto/diminuto_core.h"
#include "com/diag/codex/codex.h"
#include "../src/codex.h"
#include "unittest-codex.h"
#include <string.h>
#include <stdio.h>

int main(char * argc, char ** argv)
{

	(void)diminuto_core_enable();

	diminuto_log_setmask();

	{
		unsigned long openssl_version_number = 0;
		const char * openssl_version_text = "";
		unsigned long major, minor, fix, patch, status;

		TEST();

#ifdef OPENSSL_VERSION_NUMBER
		openssl_version_number = OPENSSL_VERSION_NUMBER;
#endif

#ifdef OPENSSL_VERSION_TEXT
		openssl_version_text = OPENSSL_VERSION_TEXT;
#endif

		major  = (openssl_version_number & 0xf0000000) >> 28;
		minor  = (openssl_version_number & 0x0ff00000) >> 20;
		fix    = (openssl_version_number & 0x000ff000) >> 12;
		patch  = (openssl_version_number & 0x00000ff0) >>  4;
		status = (openssl_version_number & 0x0000000f) >>  0;

		COMMENT("openssl_version_number=0x%08x\n", openssl_version_number);
		COMMENT("openssl_version_text=\"%s\"\n", openssl_version_text);
		COMMENT("openssl_version_decode=%u.%u.%u.%u.%u\n", major, minor, fix, patch, status);

		STATUS();
	}

	{
		TEST();

#ifdef COM_DIAG_CODEX_PLATFORM
		ASSERT(COM_DIAG_CODEX_PLATFORM != (const char *)0);
		COMMENT("COM_DIAG_CODEX_PLATFORM=\"%s\"\n", COM_DIAG_CODEX_PLATFORM);
		EXPECT(COM_DIAG_CODEX_PLATFORM[0] != '\0');
#endif

#ifdef COM_DIAG_CODEX_PLATFORM_OPENSSL
		COMMENT("COM_DIAG_CODEX_PLATFORM_OPENSSL=0x%8.8x\n", COM_DIAG_CODEX_PLATFORM_OPENSSL);
#endif

#ifdef COM_DIAG_CODEX_PLATFORM_OPENSSL_1_0_1
		COMMENT("COM_DIAG_CODEX_PLATFORM_OPENSSL_1_0_1=%d\n", COM_DIAG_CODEX_PLATFORM_OPENSSL_1_0_1);
#endif

#ifdef COM_DIAG_CODEX_PLATFORM_OPENSSL_1_0_2
		COMMENT("COM_DIAG_CODEX_PLATFORM_OPENSSL_1_0_2=%d\n", COM_DIAG_CODEX_PLATFORM_OPENSSL_1_0_2);
#endif

#ifdef COM_DIAG_CODEX_PLATFORM_OPENSSL_1_1_1
		COMMENT("COM_DIAG_CODEX_PLATFORM_OPENSSL_1_1_1=%d\n", COM_DIAG_CODEX_PLATFORM_OPENSSL_1_1_1);
#endif

#ifdef OPENSSL_IS_BORINGSS
		COMMENT("OPENSSL_IS_BORINGSS=(defined)\n");
#endif

#ifdef COM_DIAG_CODEX_PLATFORM_BORINGSSL
		COMMENT("COM_DIAG_CODEX_PLATFORM_BORINGSSL=0x%8.8x\n", COM_DIAG_CODEX_PLATFORM_BORINGSSL);
#endif

#ifdef COM_DIAG_CODEX_PLATFORM_BORINGSSL_1_1_0
		COMMENT("COM_DIAG_CODEX_PLATFORM_BORINGSSL_1_1_0=%d\n", COM_DIAG_CODEX_PLATFORM_BORINGSSL_1_1_0);
#endif

		STATUS();
	}

	{
		codex_method_t wasp;
		codex_method_t nowp;
		const SSL_METHOD * meth;
		const char * was;
		const char * now;
		int iwas;
		int inow;
		const char * val;

		TEST();

		wasp = codex_set_method(NULL);
		ASSERT(wasp != (codex_method_t)0);
		COMMENT("codex_method=%p\n", wasp);
		meth = (*wasp)();
		EXPECT(meth != (SSL_METHOD *)0);
		nowp = codex_set_method(TLSv1_method);
		EXPECT(nowp != (codex_method_t)0);
		EXPECT(nowp == wasp);
		nowp = codex_set_method(wasp);
		EXPECT(nowp != (codex_method_t)0);
		nowp = codex_set_method(NULL);
		EXPECT(nowp == wasp);

		iwas = codex_set_certificate_depth(-1);
		COMMENT("codex_certificate_depth=%d\n", iwas);
		EXPECT(iwas >= 0);
		inow = codex_set_certificate_depth(iwas + 1);
		EXPECT(inow == iwas);
		inow = codex_set_certificate_depth(-1);
		EXPECT(inow == (iwas + 1));
		inow = codex_set_certificate_depth(iwas);
		EXPECT(inow == (iwas + 1));
		inow = codex_set_certificate_depth(-1);
		EXPECT(inow == iwas);

		iwas = codex_set_self_signed_certificates(-1);
		COMMENT("codex_self_signed_certificates=%d\n", iwas);
		EXPECT(iwas >= 0);
		inow = codex_set_self_signed_certificates(1);
		EXPECT(inow == iwas);
		inow = codex_set_self_signed_certificates(-1);
		EXPECT(inow == 1);
		inow = codex_set_self_signed_certificates(iwas);
		EXPECT(inow == 1);
		inow = codex_set_self_signed_certificates(-1);
		EXPECT(inow == iwas);

		was = codex_set_cipher_list(NULL);
		ASSERT(was != (const char *)0);
		COMMENT("codex_cipher_list=\"%s\"\n", was);
		EXPECT(*was != '\0');
		now = codex_set_cipher_list("FIPS");
		EXPECT(now != (const char *)0);
		EXPECT(now == was);
		now = codex_set_cipher_list(was);
		EXPECT(now != (const char *)0);
		EXPECT(*now != '\0');
		now = codex_set_cipher_list(NULL);
		EXPECT(now == was);

		was = codex_set_session_id_context(NULL);
		ASSERT(was != (const char *)0);
		COMMENT("codex_session_id_context=\"%s\"\n", was);
		EXPECT(*was != '\0');
		now = codex_set_session_id_context("com-prairiethorn-codex");
		EXPECT(now != (const char *)0);
		EXPECT(now == was);
		now = codex_set_session_id_context(was);
		EXPECT(now != (const char *)0);
		EXPECT(*now != '\0');
		now = codex_set_session_id_context(NULL);
		EXPECT(now == was);

		was = codex_set_server_password_env(NULL);
		ASSERT(was != (char *)0);
		EXPECT(*was != '\0');
		val = getenv(was);
		ASSERT(val != (const char *)0);
		ADVISE(*val != '\0');
		COMMENT("%s=%s\n", was, (val != (const char *)0) ? "(defined)" : "(UNDEFINED)");
		now = codex_set_server_password_env("com-pairiethorn-server");
		EXPECT(now != (const char *)0);
		EXPECT(*now != '\0');
		now = codex_set_server_password_env(was);
		EXPECT(now != (const char *)0);
		EXPECT(*now != '\0');
		now = codex_set_server_password_env(NULL);
		EXPECT(now != (const char *)0);
		EXPECT(now == was);

		was = codex_set_client_password_env(NULL);
		ASSERT(was != (char *)0);
		EXPECT(*was != '\0');
		val = getenv(was);
		ASSERT(val != (const char *)0);
		ADVISE(*val != '\0');
		COMMENT("%s=%s\n", was, (val != (const char *)0) ? "(defined)" : "(UNDEFINED)");
		now = codex_set_client_password_env("com-pairiethorn-client");
		EXPECT(now != (const char *)0);
		EXPECT(*now != '\0');
		now = codex_set_client_password_env(was);
		EXPECT(now != (const char *)0);
		EXPECT(*now != '\0');
		now = codex_set_client_password_env(NULL);
		EXPECT(now != (const char *)0);
		EXPECT(now == was);

		STATUS();
	}

	{
		int rc;

		TEST();

		rc = codex_initialize(COM_DIAG_CODEX_OUT_CRT_PATH "/" "dh.pem");
		EXPECT(rc == 0);

		rc = codex_initialize(COM_DIAG_CODEX_OUT_CRT_PATH "/" "dh.pem");
		EXPECT(rc == 0);

		rc = codex_initialize(COM_DIAG_CODEX_OUT_CRT_PATH "/" "dh.pem");
		EXPECT(rc == 0);

		STATUS();
	}

	{
		DH * pdh = (DH *)0;
		DH * dh;
		int exp;
		int key;

		TEST();

		for (exp = 0; exp <= 1; ++exp) {
			for (key = 256; key <= 2048; key *= 2) {

				dh = codex_diffiehellman_callback((SSL *)0, exp, key);
				EXPECT(dh != (DH *)0);
				if (pdh == (DH *)0) { pdh = dh; }
				EXPECT(dh == pdh);

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
