/* vi: set ts=4 expandtab shiftwidth=4: */

/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 *
 * This header file can be included more than once! The "magic"
 * macro will be defined by the translation unit including it.
 */

#if !defined(CODEX_SETTOR)
#	define CODEX_SETTOR(_NAME_, _TYPE_, _UNDEFINED_, _DEFAULT_)
#endif

CODEX_SETTOR(method, codex_method_t, 0, (COM_DIAG_CODEX_METHOD))

CODEX_SETTOR(client_password_env, const char *, 0, (COM_DIAG_CODEX_CLIENT_PASSWORD_ENV))

CODEX_SETTOR(server_password_env, const char *, 0, (COM_DIAG_CODEX_SERVER_PASSWORD_ENV))

CODEX_SETTOR(cipher_list, const char *, 0, (COM_DIAG_CODEX_CIPHER_LIST))

CODEX_SETTOR(session_id_context, const char *, 0, (COM_DIAG_CODEX_SESSION_ID_CONTEXT))

CODEX_SETTOR(self_signed_certificates, int, -1, (COM_DIAG_CODEX_SELF_SIGNED_CERTIFICATES))

CODEX_SETTOR(certificate_depth, int, -1, (COM_DIAG_CODEX_CERTIFICATE_DEPTH))
