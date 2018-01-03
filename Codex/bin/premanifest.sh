
#/bin/bash
# vi: set ts=4:
# Copyright 2018 Digital Aggregates Corporation.
# Licensed under the terms in LICENSE.txt.

ZERO=$(basename $0 .sh)

CERTIFICATE="${ZERO}.crt"
EXPIRATION="365"
PRIVATEKEY="${ZERO}.pem"
BUNDLE="${ZERO}.p12"

while getopts "c:d:hk:" OPT; do
	case ${OPT} in
	c)
		CERTIFICATE="${OPTARG}"
		;;
	d)
		EXPIRATION="${OPTARG}"
		;;
	h)
		echo "usage: ${ZERO}  [ -c CERTIFICATE ] [ -d EXPIRATION ] [ -k PRIVATEKEY ]" 1>&2
		;;
	k)
		PRIVATEKEY="${OPTARG}"
		;;
	p)
		BUNDLE="${OPTARG}"
		;;
	esac
done

shift $((OPTIND - 1))

openssl req -x509 -newkey rsa:4096 -nodes -keyout ${PRIVATEKEY} -out ${CERTIFICATE} -days ${EXPIRATION} || exit 2
openssl pkcs12 -inkey ${PRIVATEKEY} -in ${CERTIFICATE} -export -out ${BUNDLE} || exit 3
openssl pkcs12 -in ${BUNDLE} -noout -info || exit 4

exit 0
