#/bin/bash
# vi: set ts=4:
# Copyright 2018 Digital Aggregates Corporation.
# Licensed under the terms in LICENSE.txt.

ZERO=$(basename $0 .sh)

CERTIFICATE="./codex.crt"
MANIFEST="./codex.dat"
CLEARTEXT=""
TEMPTEXT=""

while getopts "c:hi:o:" OPT; do
	case ${OPT} in
	c)
		CERTIFICATE="${OPTARG}"
		;;
	h)
		echo "usage: ${ZERO} [ -c CERTIFICATE.crt ] [ -i MANIFEST.dat ] [ -o CLEARTEXT.txt ] [ -t TEMPTEXT.txt ]" 1>&2
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

TEMPFILES=""

if [[ -z "${TEMPTEXT}" ]]; then
	TEMPTEXT=$(mktemp ${TMPDIR:="/tmp"}/${ZERO}.XXXXXXXXXX)
	TEMPFILES="${TEMPFILES} ${TEMPTEXT}"
fi

if [[ -z "${CLEARTEXT}" ]]; then
	CLEARTEXT=$(mktemp ${TMPDIR:="/tmp"}/${ZERO}.XXXXXXXXXX)
	TEMPFILES="${TEMPFILES} ${CLEARTEXT}"
fi

if [[ -n "${TEMPFILES}" ]]; then
	trap "rm -f ${TEMPFILES}" HUP INT TERM EXIT
fi

eval openssl smime -verify -in ${MANIFEST} -out ${TEMPTEXT} -certfile ${CERTIFICATE} -noverify || exit 2
sed -e 's/\r//g' < ${TEMPTEXT} > ${CLEARTEXT} || exit 3
sha1sum -c ${CLEARTEXT} || exit 4

exit 0
