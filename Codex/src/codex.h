/* vi: set ts=4 expandtab shiftwidth=4: */
#ifndef _H_COM_DIAG_CODEX_CODEX_PRIVATE_
#define _H_COM_DIAG_CODEX_CODEX_PRIVATE_

/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock <coverclock@diag.com><BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 *
 * Typically these are elements exposed for unit testing and not part of the
 * public API.
 */

#define COM_DIAG_CODEX_SERVER_PASSWORD_ENV "COM_DIAG_CODEX_SERVER_PASSWORD"

#define COM_DIAG_CODEX_CLIENT_PASSWORD_ENV "COM_DIAG_CODEX_CLIENT_PASSWORD"

#define COM_DIAG_CODEX_OUT_ETC_PATH "out/host/etc"

#define COM_DIAG_CODEX_CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MDF:@STRENGTH"

extern DH * codex_dh512;

extern DH * codex_dh1024;

extern DH * codex_dh2048;

extern DH * codex_dh4096;


#endif
