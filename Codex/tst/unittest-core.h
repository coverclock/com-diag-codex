/* vi: set ts=4 expandtab shiftwidth=4: */
#ifndef _H_COM_DIAG_CODEX_UNITTEST_
#define _H_COM_DIAG_CODEX_UNITTEST_

/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock <coverclock@diag.com><BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 */

/*******************************************************************************
 * PARAMETERS
 ******************************************************************************/

#undef COM_DIAG_CODEX_CIPHER_LIST

#undef COM_DIAG_CODEX_SESSION_ID_CONTEXT

#undef COM_DIAG_CODEX_CERTIFICATE_DEPTH

#undef COM_DIAG_CODEX_RENEGOTIATE_BYTES

#undef COM_DIAG_CODEX_RENEGOTIATE_SECONDS

/*******************************************************************************
 * GENERATORS
 ******************************************************************************/

/**
 * Generates the path that points to the certificates used by the unit tests.
 */
#define COM_DIAG_CODEX_OUT_CRT_PATH "out/host/crt"

#endif
