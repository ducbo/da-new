#!/bin/bash

if [ ! -d /etc/virtual/usage ]; then
	exit 0
fi

for DA_USERDIR in /usr/local/directadmin/data/users/*; do
	[ -d "${DA_USERDIR}" ] || break
	USERNAME="$(basename "${DA_USERDIR}")"

	#users usage
	BW_FILE="/etc/virtual/usage/${USERNAME}.bytes"
	echo "0=type=timestamp&time=$(date +%s)" >> "${DA_USERDIR}/bandwidth.tally"
	if [ -s "${BW_FILE}" ]; then
		cat "${BW_FILE}" >> "${DA_USERDIR}/bandwidth.tally"
	else
		echo "rotate_email_usage.sh: cannot find ${BW_FILE}"
	fi

	#user dovecot.bytes
	U_BYTES_FILE="${DA_USERDIR}/dovecot.bytes"
	if [ -s "${U_BYTES_FILE}" ]; then
		cat "${U_BYTES_FILE}" >> "${DA_USERDIR}/bandwidth.tally"
		rm -f "${U_BYTES_FILE}"
	fi

	#domain dovecot.bytes entries.
	while IFS= read -r DOMAIN; do
		D_BYTES_FILE="/etc/virtual/${DOMAIN}/dovecot.bytes"
		if [ -s "${D_BYTES_FILE}" ]; then
			cat "${D_BYTES_FILE}" >> "${DA_USERDIR}/bandwidth.tally"
			rm -f "${D_BYTES_FILE}"
		fi
	done < "/usr/local/directadmin/data/users/${USERNAME}/domains.list"
done

#cleanup user mail usage
rm -rf /etc/virtual/usage/*

#reset per-email sent counts:
rm -f /etc/virtual/*/usage/*

exit 0