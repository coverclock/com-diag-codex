/* vi: set ts=4 expandtab shiftwidth=4: */
/**
 * @file
 *
 * Copyright 2018 Digital Aggregates Corporation, Colorado, USA<BR>
 * Licensed under the terms in LICENSE.txt<BR>
 * Chip Overclock (mailto:coverclock@diag.com)<BR>
 * https://github.com/coverclock/com-diag-codex<BR>
 *
 * See the README.md for a list of references.
 */

/*******************************************************************************
 * HEADERS
 ******************************************************************************/

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <stdio.h>
#include "com/diag/codex/codex.h"
#include "com/diag/diminuto/diminuto_criticalsection.h"
#include "com/diag/diminuto/diminuto_log.h"
#include "com/diag/diminuto/diminuto_delay.h"
#include "com/diag/diminuto/diminuto_types.h"
#include "com/diag/diminuto/diminuto_ipc4.h"
#include "com/diag/diminuto/diminuto_ipc6.h"
#include "codex.h"

/*******************************************************************************
 * PARAMETERS
 ******************************************************************************/

#undef COM_DIAG_CODEX_SETTOR
#define COM_DIAG_CODEX_SETTOR(_NAME_, _TYPE_, _UNDEFINED_, _DEFAULT_) \
	extern _TYPE_ codex_##_NAME_;

#include "codex_parameters.h"

/*******************************************************************************
 * DEBUGGING
 ******************************************************************************/

#if 0
#	define CODEX_WTF ((void)fprintf(stderr, "CODEX_WTF: %s[%d]\n", __FILE__, __LINE__))
#else
#	define CODEX_WTF ((void)0)
#endif

/*******************************************************************************
 * CALLBACKS
 ******************************************************************************/

int codex_verification_callback(int ok, X509_STORE_CTX * ctx)
{
	X509 * crt = (X509 *)0;
	X509_NAME * nam = (X509_NAME *)0;
	int depth = -1;
	int error = 0;
	const char * text = (const char *)0;
	char name[256];

	depth = X509_STORE_CTX_get_error_depth(ctx);

	crt = X509_STORE_CTX_get_current_cert(ctx);
	if (crt != (X509 *)0) {

		/*
		 * These fields are deliberately displayed in the same order as when
		 * using the "openssl x509 -subject -issuer -noout" command.
		 */

		name[0] = '\0';
		nam = X509_get_issuer_name(crt);
		if (nam != (X509_NAME *)0) {
			X509_NAME_oneline(nam, name, sizeof(name));
			name[sizeof(name) - 1] = '\0';
		}
		DIMINUTO_LOG_INFORMATION("codex_verification_callback: x509 ctx=%p crt=%p subject[%d]=\"%s\"\n", ctx, crt, depth, name);

		name[0] = '\0';
		nam = X509_get_issuer_name(crt);
		if (nam != (X509_NAME *)0) {
			X509_NAME_oneline(nam, name, sizeof(name));
			name[sizeof(name) - 1] = '\0';
		}
		DIMINUTO_LOG_INFORMATION("codex_verification_callback: x509 ctx=%p crt=%p issuer[%d]=\"%s\"\n", ctx, crt, depth, name);

	}

	if (!ok) {

		error = X509_STORE_CTX_get_error(ctx);
		text = X509_verify_cert_error_string(error);
		DIMINUTO_LOG_NOTICE("codex_verification_callback: x509 ctx=%p crt=%p error=%d=\"%s\"\n", ctx, crt, error, (text != (const char *)0) ? text : "");

		switch (error) {

		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
			if (codex_self_signed_certificates) {
				DIMINUTO_LOG_NOTICE("codex_verification_callback: x509 ctx=%p crt=%p self_signed_certificates=%d\n", ctx, crt, codex_self_signed_certificates);
				ok = 1;
			}
			break;

		default:
			/* Do nothing. */
			break;

		}

	}

	/*
	 * Surely if the certificate pointer returned by X509_STORE is null, then
	 * OpenSSL's own validator would not have verified it. But never the less,
	 * we check.
	 */

	if (crt != (X509 *)0) {
		/* Do nothing. */
	} else if (!ok) {
		/* Do nothing. */
	} else {
		DIMINUTO_LOG_NOTICE("codex_verification_callback: ctx=%p crt=%p ok=%d\n", ctx, crt, ok);
		ok = 0;
	}

	return ok;
}

/*******************************************************************************
 * VERIFICATION
 ******************************************************************************/

/*
 * This was mostly written by reverse engineering X509V3_EXT_print() in
 * crypto/x509v3/v3_prn.c from https://github.com/openssl/openssl. I
 * have tried to exercise all the nominal paths, but no guarantees.
 */
int codex_connection_verify(codex_connection_t * ssl, const char * expected)
{
	int result = CODEX_VERIFY_FAILED;
	long error = X509_V_ERR_APPLICATION_VERIFICATION;
	X509 * crt = (X509 *)0;
	X509_NAME * subject = (X509_NAME *)0;
	ASN1_INTEGER * srl = (ASN1_INTEGER *)0;
	char srn[(20 /* RFC 5280 4.1.2.2 */ * 2) + 1] = { '\0' };
	int count = 0;
	X509_EXTENSION * ext = (X509_EXTENSION *)0;
	int ii = 0;
	ASN1_OBJECT * obj = (ASN1_OBJECT *)0;
	int nid = -1;
	const char * str = (char *)0;
	const X509V3_EXT_METHOD * meth = (X509V3_EXT_METHOD *)0;
	void * ptr = (void *)0;
	STACK_OF(CONF_VALUE) * vals = (STACK_OF(CONF_VALUE) *)0;
	int jj = 0;
	CONF_VALUE * val = (CONF_VALUE *)0;
	int lim = 0;
	X509_NAME * nam = (X509_NAME *)0;
	int rc = -1;
	const char * text = (const char *)0;
	char * value = (char *)0;
	const unsigned char * p = (const unsigned char *)0;
	ASN1_OCTET_STRING * extoct = (ASN1_OCTET_STRING *)0;
	int extlen = 0;
	const ASN1_ITEM * it = (const ASN1_ITEM *)0;
	char buffer[256] = { '\0' };
	int fd = -1;
	diminuto_ipv4_t farend4 = 0;
	diminuto_ipv6_t farend6 = { 0 };
	diminuto_ipv4_t * address4 = (diminuto_ipv4_t *)0;
	diminuto_ipv6_t * address6 = (diminuto_ipv6_t *)0;
	diminuto_ipv4_t * addresses4 = (diminuto_ipv4_t *)0;
	diminuto_ipv6_t * addresses6 = (diminuto_ipv6_t *)0;
	diminuto_ipv4_buffer_t buffer4 = { '\0' };
	diminuto_ipv6_buffer_t buffer6 = { '\0' };
	diminuto_ipv4_buffer_t debug4 = { '\0' };
	diminuto_ipv6_buffer_t debug6 = { '\0' };
	const char * anycn = "";
	const char * anyfqdn = "";
	const char * cn = (const char *)0;
	const char * fqdn = (const char *)0;

	do {

		/*
		 * Before we descend into the certificate, we get our IPv4 and/or
		 * IPv6 addresses from the far end of the SSL connection. If we don't
		 * have one or the other (which should be impossible), we reject
		 * this connection.
		 */

		fd = SSL_get_fd(ssl);
		if (fd < 0) {
			DIMINUTO_LOG_ERROR("codex_connection_verify: fd ssl=%p crt=%p fd=%d\n", ssl, crt, fd);
			break;
		}

		farend4 = DIMINUTO_IPC4_UNSPECIFIED;
		rc = diminuto_ipc4_farend(fd, &farend4, (diminuto_port_t *)0);
		if (rc < 0) {
			DIMINUTO_LOG_ERROR("codex_connection_verify: ipc4 ssl=%p crt=%p rc=%d\n", ssl, crt, rc);
			break;
		}

		diminuto_ipc4_address2string(farend4, buffer4, sizeof(buffer4));

		farend6 = DIMINUTO_IPC6_UNSPECIFIED;
		rc = diminuto_ipc6_farend(fd, &farend6, (diminuto_port_t *)0);
		if (rc < 0) {
			DIMINUTO_LOG_ERROR("codex_connection_verify: ipc6 ssl=%p crt=%p rc=%d\n", ssl, crt, rc);
			break;
		}

		diminuto_ipc6_address2string(farend6, buffer6, sizeof(buffer6));

		if (!diminuto_ipc4_is_unspecified(&farend4)) {
			/* Do nothing. */
		} else if (!diminuto_ipc6_is_unspecified(&farend6)) {
			/* Do nothing. */
		} else {
			DIMINUTO_LOG_ERROR("codex_connection_verify: farend ssl=%p IPv4=%s IPv6=%s\n", ssl, buffer4, buffer6); /* Should be impossible. */
			break;
		}

		DIMINUTO_LOG_DEBUG("codex_connection_verify: farend ssl=%p IPv4=%s IPv6=%s\n", ssl, buffer4, buffer6);

		/*
		 * Get the peer certificate and its serial number (at most 20 bytes).
		 */

		crt = SSL_get_peer_certificate(ssl);
		if (crt == (X509 *)0) {
			DIMINUTO_LOG_WARNING("codex_connection_verify: crt ssl=%p crt=%p\n", ssl, crt);
			break;
		}

		srl = X509_get_serialNumber(crt);
		if (srl == (ASN1_INTEGER *)0) {
			DIMINUTO_LOG_WARNING("codex_connection_verify: srl ssl=%p crt=%p srl=%p\n", ssl, crt, srl);
			break;
		}

		for (ii = 0; (ii < srl->length) && (ii < ((sizeof(srn) - 1) / 2)); ++ii) {
			jj = (srl->data[ii] & 0xf0) >> 4;
			srn[ii * 2] = (jj < 0xa) ? '0' + jj : 'A' + jj - 10;
			jj = (srl->data[ii] & 0x0f);
			srn[(ii * 2) + 1] = (jj < 0xa) ? '0' + jj : 'A' + jj - 10;
		}
		srn[ii * 2] = '\0';

		DIMINUTO_LOG_DEBUG("codex_connection_verify: srl ssl=%p crt=%p SRL=%s\n", ssl, crt, srn);

		/*
		 * Next we check for a match against the Common Name (CN). We extract
		 * the CN even if we expect nothing, as a way of validity checking the
		 * certificate. If the certificate has no CN, we reject it, even if
		 * we don't care what the CN is.
		 */

		nam = X509_get_subject_name(crt);
		if (nam == (X509_NAME *)0) {
			DIMINUTO_LOG_WARNING("codex_connection_verify: nam ssl=%p crt=%p cn=%p\n", ssl, crt, nam);
			break;
		}

		buffer[0] = '\0';
		rc = X509_NAME_get_text_by_NID(nam, NID_commonName, buffer, sizeof(buffer));
		if (rc <= 0) {
			DIMINUTO_LOG_WARNING("codex_connection_verify: text ssl=%p crt=%p [cn]=%d\n", ssl, crt, rc);
			break;
		}
		buffer[sizeof(buffer) - 1] = '\0';

		anycn = buffer;
		DIMINUTO_LOG_DEBUG("codex_connection_verify: nid ssl=%p crt=%p \"%s\"=\"%s\"\n", ssl, crt, SN_commonName, anycn);

		if (expected == (const char *)0) {

			/*
			 * The certificate has a CN and seems otherwise valid, but the
			 * application chooses not to expect any CN or FQDN.
			 */

			result |= CODEX_VERIFY_PASSED;
			DIMINUTO_LOG_INFORMATION("codex_connection_verify: nil ssl=%p crt=%p SRL=%s CN=\"%s\" expected=%p mask=0x%x\n", ssl, crt, srn, anycn, expected, result);

		} else if (strcasecmp(anycn, expected) == 0) {

			/*
			 * The CN matches. If that's the only verification that occurs, the
			 * application must decide if that's sufficient.
			 */

			cn = anycn;
			result |= CODEX_VERIFY_CN;
			DIMINUTO_LOG_INFORMATION("codex_connection_verify: cn ssl=%p crt=%p SRL=%s CN=\"%s\" mask=0x%x\n", ssl, crt, srn, cn, result);

		} else {
			/* Do nothing. */
		}

		/*
		 * Even if the CN matches, we still walk the certificate looking at the
		 * Fully Qualified Domain Names (FQDNs).
		 */

		count = X509_get_ext_count(crt);
		DIMINUTO_LOG_DEBUG("codex_connection_verify: count ssl=%p crt=%p extensions=%d\n", ssl, crt, count);
		for (ii = 0; ii < count; ++ii) {

			ext = X509_get_ext(crt, ii);
			if (ext == (X509_EXTENSION *)0) {
				CODEX_WTF;
				continue;
			}

			obj = X509_EXTENSION_get_object(ext);
			if (obj == (ASN1_OBJECT *)0) {
				CODEX_WTF;
				continue;
			}

			nid = OBJ_obj2nid(obj);
			if (nid == NID_undef) {
				CODEX_WTF;
				continue;
			}

			str = OBJ_nid2sn(nid);
			if (str == (const char *)0) {
				CODEX_WTF;
				continue;
			}

			DIMINUTO_LOG_DEBUG("codex_connection_verify: nid2sn ssl=%p crt=%p str=\"%s\"\n", ssl, crt, str);

			if (strcmp(str, COM_DIAG_CODEX_SHORTNAME_SUBJECTALTNAME) != 0) {
				CODEX_WTF;
				continue;
			}

			extoct = X509_EXTENSION_get_data(ext);
			if (extoct == (ASN1_OCTET_STRING *)0) {
				CODEX_WTF;
				continue;
			}

			extlen = ASN1_STRING_length(extoct);

			/*
			 * The function X509V3_EXT_print() uses ASN1_STRING_get0_data()
			 * to extract this value. But even though that function uses it, and
			 * I find the function in the ASN.1 library in libcrypto, and
			 * there's a function prototype for it in the openssl/asn1.h header
			 * file, and a man page for it on the OpenSSL.org web site, the
			 * linker can't find it. Weird.
			 */

			p = extoct->data; /* ?ASN1_STRING_get0_data(extoct)? */
			if (p == (const unsigned char *)0) {
				CODEX_WTF;
				continue;
			}

			meth = X509V3_EXT_get(ext);
			if (meth == (X509V3_EXT_METHOD *)0) {
				CODEX_WTF;
				continue;
			}

			it = ASN1_ITEM_ptr(meth->it);

			if (it != (ASN1_ITEM_EXP *)0) {

				ptr = ASN1_item_d2i((ASN1_VALUE **)0, &p, extlen, it);
				if (ptr == (void *)0) {
					CODEX_WTF;
					continue;
				}

			} else if (meth->d2i != (X509V3_EXT_D2I)0) {

				ptr = meth->d2i((void *)0, &p, extlen);
				if (ptr == (void *)0) {
					CODEX_WTF;
					continue;
				}

			} else {

				CODEX_WTF;
				continue;

			}

			if (meth->i2v == (X509V3_EXT_I2V)0) {
				CODEX_WTF;
				continue;
			}

			vals = meth->i2v(meth, ptr, (STACK_OF(CONF_VALUE) *)0);
			if (vals == (STACK_OF(CONF_VALUE) *)0) {
				CODEX_WTF;
				continue;
			}

			lim = sk_CONF_VALUE_num(vals);
			DIMINUTO_LOG_DEBUG("codex_connection_verify: num ssl=%p crt=%p stack=%d\n", ssl, crt, lim);
			for (jj = 0; jj < lim; ++jj) {

				val = sk_CONF_VALUE_value(vals, jj);
				if (val == (CONF_VALUE *)0) {
					CODEX_WTF;
					continue;
				}

				if (val->name == (char *)0) {
					CODEX_WTF;
					continue;
				}

				if (val->value == (char *)0) {
					CODEX_WTF;
					continue;
				}

				DIMINUTO_LOG_DEBUG("codex_connection_verify: vector ssl=%p crt=%p \"%s\"=\"%s\"\n", ssl, crt, val->name, val->value);

				if (strcmp(val->name, COM_DIAG_CODEX_CONFNAME_DNS) != 0) {
					CODEX_WTF;
					continue;
				}

				/*
				 * If the certificate contains FQDNs coded as DNS values, then
				 * the SSL connection *must* be coming from an IPv4 or IPv6
				 * address that matches an address resolved from a FQDN via
				 * DNS. If an FQDN has both an IPv4 and an IPv6 address, only
				 * ONE of them must match. Here's an example of why this is the
				 * case. Depending on how a host is configured, its IPv4 DNS
				 * address for "localhost" could be 127.0.0.1 and its IPv6 DNS
				 * address can legitimately be either ::ffff:127.0.0.1 or ::1.
				 * The former is an IPv4 address cast in IPv6-compatible form,
				 * and the latter is the standard IPv6 address for "localhost".
				 * Either is valid. If the host on "localhost" connects via
				 * IPv4, its far end IPv4 address will be 127.0.0.1 and its
				 * IPv6 address will be ::ffff:127.0.0.1. If it connects via
				 * IPv6, they may be 0.0.0.0 (because there is no IPv4-
				 * compatible form of its IPv6 address) and ::1.
				 */

				anyfqdn = val->value;

				if (!diminuto_ipc4_is_unspecified(&farend4)) {
					addresses4 = diminuto_ipc4_addresses(anyfqdn);
					if (addresses4 != (diminuto_ipv4_t *)0) {
						for (address4 = addresses4; !diminuto_ipc4_is_unspecified(address4); ++address4) {
							DIMINUTO_LOG_DEBUG("codex_connection_verify: dns4 ssl=%p crt=%p FQDN=\"%s\" IPv4=%s\n", ssl, crt, anyfqdn, diminuto_ipc4_address2string(*address4, debug4, sizeof(debug4)), result);
							if (diminuto_ipc4_compare(address4, &farend4) == 0) {

								/*
								 * The DNS resolution of this FQDN matches the
								 * IPv4 address associated with the far end.
								 */

								result |= (CODEX_VERIFY_IPV4 | CODEX_VERIFY_DNS);
								DIMINUTO_LOG_INFORMATION("codex_connection_verify: dns ssl=%p crt=%p SRL=%s CN=\"%s\" FQDN=\"%s\" IPv4=%s mask=0x%x\n", ssl, crt, srn, anycn, anyfqdn, buffer4, result);
								break;

							}
						}
						free(addresses4);
					}
				}

				if (!diminuto_ipc6_is_unspecified(&farend6)) {
					addresses6 = diminuto_ipc6_addresses(anyfqdn);
					if (addresses6 != (diminuto_ipv6_t *)0) {
						for (address6 = addresses6; !diminuto_ipc6_is_unspecified(address6); ++address6) {
							DIMINUTO_LOG_DEBUG("codex_connection_verify: dns6 ssl=%p crt=%p FQDN=\"%s\" IPv6=%s\n", ssl, crt, anyfqdn, diminuto_ipc6_address2string(*address6, debug6, sizeof(debug6)), result);
							if (diminuto_ipc6_compare(address6, &farend6) == 0) {

								/*
								 * The DNS resolution of this FQDN matches the
								 * IPv6 address associated with the far end.
								 */

								result |= (CODEX_VERIFY_IPV6 | CODEX_VERIFY_DNS);
								DIMINUTO_LOG_INFORMATION("codex_connection_verify: dns ssl=%p crt=%p SRL=%s CN=\"%s\" FQDN=\"%s\" IPv6=%s mask=0x%x\n", ssl, crt, srn, anycn, anyfqdn, buffer6, result);
								break;

							}
						}
						free(addresses6);
					}
				}

				/*
				 * Finally, we check to see if the FQDN matches our expected
				 * value. Note that the matching FQDN doesn't have to resolve
				 * via DNS to the IP address of the far end; merely *some* FQDN
				 * in the certificate has to do so.
				 */

				if (expected == (const char *)0) {
					/* Do nothing. */
				} else  if (strcmp(anyfqdn, expected) != 0) {
					/* Do nothing. */
				} else {

					/*
					 * The FQDN matches our expected value.
					 */

					fqdn = anyfqdn;
					result |= CODEX_VERIFY_FQDN;
					DIMINUTO_LOG_INFORMATION("codex_connection_verify: fqdn ssl=%p crt=%p SRL=%s CN=\"%s\" FQDN=\"%s\" mask=0x%x\n", ssl, crt, srn, anycn, fqdn, result);

				}

			}

		}

	} while (false);

	/*
	 * Now we see what SSL thought of the certificate. If the error is that the
	 * certificate is self-signed, we check the (sadly) global option to accept
	 * self-signed certificates. If it is set, we complain, but go ahead and
	 * change the error code back to OK. But if SSL was happy with the
	 * certificate, but we were not, we change the error code to indicate an
	 * application failure.
	 */

	error = SSL_get_verify_result(ssl);
	switch (error) {

		case X509_V_OK:
			if (result == CODEX_VERIFY_FAILED) {
				error = X509_V_ERR_APPLICATION_VERIFICATION;
			}
			break;

		case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
		case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
			if (codex_self_signed_certificates) {
				text = X509_verify_cert_error_string(error);
				if (text == (const char *)0) { text = ""; }
				DIMINUTO_LOG_NOTICE("codex_connection_verify: self ssl=%p crt=%p SRL=%s CN=\"%s\" error=%d=\"%s\"\n", ssl, crt, srn, anycn, error, text);
				error = X509_V_OK;
			}
			break;

		default:
			break;

	}

	if (error != X509_V_OK) {
		text = X509_verify_cert_error_string(error);
		if (text == (const char *)0) { text = ""; }
		result = CODEX_VERIFY_FAILED;
		DIMINUTO_LOG_WARNING("codex_connection_verify: x509 ssl=%p crt=%p SRL=%s CN=\"%s\" IPv4=%s IPv6=%s error=%d=\"%s\" mask=0x%x\n", ssl, crt, srn, anycn, diminuto_ipc4_address2string(farend4, buffer4, sizeof(buffer4)), diminuto_ipc6_address2string(farend6, buffer6, sizeof(buffer6)), text, result);
	}

	if (crt != (X509 *)0) {
		X509_free(crt);
	}

	return result;
}
