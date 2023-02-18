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

#if !defined(CODEX_PARAMETER)
#   warning CODEX_PARAMETER undefined!
#   define CODEX_PARAMETER(_NAME_, _TYPE_, _UNDEFINED_, _DEFAULT_)
#endif

CODEX_PARAMETER(method, codex_method_t, 0, (COM_DIAG_CODEX_METHOD))

CODEX_PARAMETER(client_password_env, const char *, 0, (COM_DIAG_CODEX_CLIENT_PASSWORD_ENV))

CODEX_PARAMETER(server_password_env, const char *, 0, (COM_DIAG_CODEX_SERVER_PASSWORD_ENV))

CODEX_PARAMETER(cipher_list, const char *, 0, (COM_DIAG_CODEX_CIPHER_LIST))

CODEX_PARAMETER(session_id_context, const char *, 0, (COM_DIAG_CODEX_SESSION_ID_CONTEXT))

CODEX_PARAMETER(self_signed_certificates, int, -1, (COM_DIAG_CODEX_SELF_SIGNED_CERTIFICATES))

CODEX_PARAMETER(certificate_depth, int, -1, (COM_DIAG_CODEX_CERTIFICATE_DEPTH))
