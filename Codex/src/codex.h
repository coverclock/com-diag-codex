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
 * Typically these are elements exposed for unit testing and are not part of
 * the public API.
 */

/*******************************************************************************
 * GENERATORS
 ******************************************************************************/

#define COM_DIAG_CODEX_SERVER_PASSWORD_ENV "COM_DIAG_CODEX_SERVER_PASSWORD"

#define COM_DIAG_CODEX_CLIENT_PASSWORD_ENV "COM_DIAG_CODEX_CLIENT_PASSWORD"

#define COM_DIAG_CODEX_OUT_ETC_PATH "out/host/etc"

/**
 * Cipher suite selection control string.
 *
 * ALL:			All cipher suites;<BR>
 * !aNULL:		except those not offering authentication;<BR>
 * !ADH:		except Anonymous Diffie Hellman suites;<BR>
 * !LOW:		except Low Strength suites;<BR>
 * !EXP:		except Export Strength suites;<BR>
 * !MD5:		except Message Digest 5 suites;<BR>
 * @STRENGTH:	and select in order of highest strength to lowest.<BR>
 *
 * Try "openssl ciphers -v" followed by the control string below (probably in
 * single quotes) to see a list of possible cipher suites.
 *
 * See ciphers(1).
 */
#define COM_DIAG_CODEX_CIPHER_LIST "ALL:!aNULL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"

#define COM_DIAG_CODEX_SHORTNAME_SUBJECTALTNAME "subjectAltName"

#define COM_DIAG_CODEX_CONFNAME_DNS "DNS"

/*******************************************************************************
 * GLOBALS
 ******************************************************************************/

extern DH * codex_dh512;

extern DH * codex_dh1024;

extern DH * codex_dh2048;

extern DH * codex_dh4096;

#endif
