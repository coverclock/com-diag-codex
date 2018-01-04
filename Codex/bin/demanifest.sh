#/bin/bash
# vi: set ts=4:
# Copyright 2018 Digital Aggregates Corporation.
# Licensed under the terms in LICENSE.txt.

ZERO=$(basename $0 .sh)

MANIFEST="./Manifest.dat"
CLEARTEXT=""
CERTIFICATE=""

while getopts "c:hi:o:" OPT; do
	case ${OPT} in
	c)
		CERTIFICATE="-certfile ${OPTARG}"
		;;
	h)
		echo "usage: ${ZERO} [ -c CERTIFICATE.crt ] [ -i MANIFEST.dat ] [ -o CLEARTEXT.txt ]" 1>&2
		exit 0
		;;
	i)
		MANIFEST="${OPTARG}"
		;;
	o)
		CLEARTEXT="${OPTARG}"
		;;
	esac
done

shift $((OPTIND - 1))

if [[ -z "${CLEARTEXT}" ]]; then
	CLEARTEXT=$(mktemp ${TMPDIR:="/tmp"}/${ZERO}.XXXXXXXXXX)
	trap "rm -f ${CLEARTEXT}" HUP INT TERM EXIT
fi

eval openssl smime -verify -in ${MANIFEST} -out ${CLEARTEXT} ${CERTIFICATE} -noverify || exit 2
sed -i -e 's/\r//g' ${CLEARTEXT} || exit 3
sha1sum -c ${CLEARTEXT} || exit 4

exit 0
