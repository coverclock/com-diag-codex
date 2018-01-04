#/bin/bash
# vi: set ts=4:
# Copyright 2018 Digital Aggregates Corporation.
# Licensed under the terms in LICENSE.txt.

ZERO=$(basename $0 .sh)

PRIVATEKEY=""
MANIFEST="./Manifest.dat"
CERTIFICATE=""

while getopts "hk:o:s:" OPT; do
	case ${OPT} in
	h)
		echo "usage: ${ZERO} [ -k PRIVATEKEY.pem ] [ -o MANIFEST.dat ] [ -s CERTIFICATE.crt ] [ -- FILE ... ]" 1>&2
		exit 0
		;;
	k)
		PRIVATEKEY="${PRIVATEKEY} -inkey ${OPTARG}"
		;;
	o)
		MANIFEST="${OPTARG}"
		;;
	s)
		CERTIFICATE="${CERTIFICATE} -signer ${OPTARG}"
		;;
	esac
done

shift $((OPTIND - 1))

sha1sum "${@}" | eval openssl smime -nocerts -sign ${PRIVATEKEY} ${CERTIFICATE} -out ${MANIFEST} || exit 2

exit 0
