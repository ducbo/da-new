#!/bin/bash
#similar to get_main_ip.sh, this returns the main IPv6 for the system.

if [ -x /sbin/ping6 ] || [ -x /usr/sbin/ping6 ]; then
    if ! ping6 -q -c 1 -W 1 api64.ipify.org >/dev/null 2>&1; then
	#ping failed, let's try one more time
	if ! ping6 -q -c 1 -W 1 api64.ipify.org >/dev/null 2>&1; then
		exit 1
	fi
    fi
fi

curl -6 --silent --connect-timeout 4 https://api64.ipify.org
exit $?
