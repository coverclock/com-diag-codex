/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2018-2022 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
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

/*
 * It's a good idea to run this with valgrind(1) to insure the heap
 * management is working correctly.
 */

int main(int argc, char ** argv)
{

	(void)diminuto_core_enable();

	diminuto_log_setmask();

	{
		int rc;

		TEST();

		rc = codex_revoked_free();
		ASSERT(rc == 0);

		STATUS();
	}

	{
		int rc;

		TEST();

		rc = codex_revoked_import("/dev/null");
		ASSERT(rc == 0);
		rc = codex_revoked_export("/dev/stderr");
		ASSERT(rc == 0);
		rc = codex_revoked_free();
		ASSERT(rc == 0);

		STATUS();
	}

	{
		int rc;

		TEST();

		rc = codex_revoked_import(COM_DIAG_CODEX_OUT_CRT_PATH "/crl.txt");
		ASSERT(rc == 2);
		rc = codex_revoked_export("/dev/stderr");
		ASSERT(rc == 2);
		rc = codex_revoked_free();
		ASSERT(rc == 2);

		STATUS();
	}

	{
		int rc;

		TEST();

		rc = codex_revoked_import(COM_DIAG_CODEX_OUT_CRT_PATH "/crltwo.txt");
		ASSERT(rc == 4);
		rc = codex_revoked_export("/dev/stderr");
		ASSERT(rc == 2);
		rc = codex_revoked_free();
		ASSERT(rc == 2);

		STATUS();
	}

	EXIT();
}
