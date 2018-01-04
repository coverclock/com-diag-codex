#/bin/bash
# vi: set ts=4:
# Copyright 2018 Digital Aggregates Corporation.
# Licensed under the terms in LICENSE.txt.
# ABSTRACT
# Generate the self-signed certificate and private key
# necessary for use with generating and verifying a
# manifest.

ZERO=$(basename $0 .sh)

CERTIFICATE="codex.crt"
CONFIGURATION="codex.cnf"
EXPIRATION="3653"
PRIVATEKEY="codex.pem"

while getopts "c:d:hk:o:" OPT; do
	case ${OPT} in
	c)
		CONFIGURATION="${OPTARG}"
		;;
	d)
		EXPIRATION="${OPTARG}"
		;;
	h)
		echo "usage: ${ZERO} [ -c CONFIGURATION.cnf ] [ -d EXPIRATION ] [ -k PRIVATEKEY.pem ] [ -o CERTIFICATE.crt ]" 1>&2
		exit 0
		;;
	k)
		PRIVATEKEY="${OPTARG}"
		;;
	o)
		CERTIFICATE="${OPTARG}"
		;;
	esac
done

shift $((OPTIND - 1))

if [[ -r ${CONFIGURATION} ]]; then
	openssl req -x509 -newkey rsa:4096 -nodes -config ${CONFIGURATION} -keyout ${PRIVATEKEY} -out ${CERTIFICATE} -days ${EXPIRATION} || exit 2
else
	openssl req -x509 -newkey rsa:4096 -nodes -keyout ${PRIVATEKEY} -out ${CERTIFICATE} -days ${EXPIRATION} || exit 2
fi

exit 0
