#!/bin/sh

set -e

LICENSE=/usr/local/directadmin/conf/license.key

if [ "$#" -ne 1 ] || [ "${#1}" -ne 44 ]; then
	echo "Usage:"
	echo "$0 <LK_hash>"
	echo ""
	echo "example: $0 vDCTEfWtQ22juwQlNkO5+5a6eWJJMxxeOwzMztoJIRQ="
	exit 1
fi

echo "$1" > ${LICENSE}
chmod 600 ${LICENSE}
systemctl restart directadmin.service
