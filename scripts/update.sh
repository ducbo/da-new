#!/bin/sh

DA_PATH=/usr/local/directadmin
DA_CONFIG=${DA_PATH}/conf/directadmin.conf
DA_SCRIPTS=${DA_PATH}/scripts
DA_TQ=${DA_PATH}/data/task.queue

# DA 1.646 systemd only
DA_INITD_SERVICE=/etc/init.d/directadmin
DA_SYSTEMD_SERVICE=/etc/systemd/system/directadmin.service
if [ -f ${DA_INITD_SERVICE} ]; then
	cp -f ${DA_SCRIPTS}/directadmin.service ${DA_SYSTEMD_SERVICE}
    rm -f "${DA_INITD_SERVICE}"
	systemctl daemon-reload
    systemctl enable directadmin.service
elif ! diff --brief ${DA_SCRIPTS}/directadmin.service ${DA_SYSTEMD_SERVICE} > /dev/null; then
	cp -f ${DA_SCRIPTS}/directadmin.service ${DA_SYSTEMD_SERVICE}
	systemctl daemon-reload
fi

if [ ! -s /etc/systemd/system/directadmin-userd@.service ] || ! diff --brief ${DA_SCRIPTS}/directadmin-userd@.service /etc/systemd/system/directadmin-userd@.service > /dev/null; then
	cp -f ${DA_SCRIPTS}/directadmin-userd@.service /etc/systemd/system/directadmin-userd@.service
	systemctl daemon-reload
fi

if [ ! -s /etc/systemd/system/directadmin-userd@.socket ] || ! diff --brief ${DA_SCRIPTS}/directadmin-userd@.socket /etc/systemd/system/directadmin-userd@.socket > /dev/null; then
	cp -f ${DA_SCRIPTS}/directadmin-userd@.socket /etc/systemd/system/directadmin-userd@.socket
	systemctl daemon-reload
fi 


if ! diff --brief ${DA_SCRIPTS}/directadmin_cron /etc/cron.d/directadmin_cron > /dev/null; then
	cp -f ${DA_SCRIPTS}/directadmin_cron /etc/cron.d/directadmin_cron
	chmod 600 /etc/cron.d/directadmin_cron
	chown root /etc/cron.d/directadmin_cron
fi

if [ -e /etc/logrotate.d ] && ! diff --brief ${DA_SCRIPTS}/directadmin.rotate /etc/logrotate.d/directadmin > /dev/null; then
	cp $DA_SCRIPTS/directadmin.rotate /etc/logrotate.d/directadmin
	chmod 644 /etc/logrotate.d/directadmin
fi

#Set permissions with current DA version.
${DA_PATH}/directadmin p

{
	echo "action=cache&value=showallusers"
	echo "action=cache&value=safemode"
	echo "action=convert&value=cronbackups"
	echo "action=convert&value=suspendedmysql"
	echo "action=syscheck"

	# Do we really need them?
	#DA 1.56.2
	#https://www.directadmin.com/features.php?id=2332
	echo 'action=rewrite&value=cron_path'
} >> $DA_TQ

#Allow all TCP/UDP outbound connections from root
if [ -e /etc/csf/csf.allow ] && [ -x /usr/sbin/csf ]; then
	if ! grep -q 'out|u=0' /etc/csf/csf.allow; then
		/usr/sbin/csf -a "tcp|out|u=0" "Added by DirectAdmin"
		/usr/sbin/csf -a "udp|out|u=0" "Added by DirectAdmin"
	fi
fi

# DA 1.63.5 remove directadmin from services.status list
SERVICES_STATUS=${DA_PATH}/data/admin/services.status
if [ -s ${SERVICES_STATUS} ] && grep -q '^directadmin=' ${SERVICES_STATUS}; then
	sed -i '/^directadmin=/d' ${SERVICES_STATUS}
fi

# DA 1.641 remove old system DB file
if [ -s "${DA_PATH}/data/admin/da.db" ]; then
	rm -f "${DA_PATH}/data/admin/da.db"
fi

# DA 1.643 replace relative tmpdir config option to absolute
# old:
#     tmpdir=../../../home/tmp
# new:
#     tmpdir=/home/tmp
if grep -q '^tmpdir=\.\./\.\./\.\./' ${DA_CONFIG}; then
	sed -i 's|^tmpdir=\.\./\.\./\.\./|tmpdir=/|' ${DA_CONFIG}
fi

# DA 1.643 unify Evolution custom translations structure by removing language
# directories. This make sure files `.../lang/{xx}/custom/lang.po` are moved
# to `../lang/custom/{xx}.po`.
EVO_LANGS=${DA_PATH}/data/skins/evolution/lang
find "${EVO_LANGS}" -path '*/custom/lang.po' -printf "%P\n" | while read -r file; do
	xx=${file%/custom/lang.po}
	if [ "${xx#*/}" != "${xx}" ]; then
		# Ignore if {xx} contains `/` symbols
		continue
	fi
	mkdir -p "${EVO_LANGS}/custom"
	mv "${EVO_LANGS}/${file}" "${EVO_LANGS}/custom/${xx}.po"
done

if [ -f ${DA_PATH}/custombuild/options.conf ]; then
	# DA 1.644 force CB cron handler to upgrade crontab-file
	${DA_PATH}/custombuild/build cron > /dev/null 2> /dev/null || true

	# Add depreciation checks
	${DA_PATH}/custombuild/build deprecation_check > /dev/null 2> /dev/null || true
fi

# DA 1.645 run custombuild cronjob from binary
rm -f /etc/cron.daily/custombuild
rm -f /etc/cron.weekly/custombuild
rm -f /etc/cron.monthly/custombuild

# DA 1.645 allow CB to run post-install tasks
${DA_PATH}/custombuild/build install

# DA 1.646 drop /etc/virtual/pophosts
rm -f /etc/virtual/pophosts
rm -f /etc/virtual/pophosts_user

# DA 1.647 remove old CustomBuild plugin
if [ -d "${DA_PATH}/plugins/custombuild" ]; then
	rm -rf "${DA_PATH}/plugins/custombuild"
	if getent passwd cb_plugin > /dev/null; then
		userdel cb_plugin
	fi
fi

# DA 1.647 auto-migrate allow/deny lists with new commands
add_command_alias_to_file() {
	old=$2
	new=$3
	if grep -q "^${old}$" "$1" && ! grep -q "^${new}$" "$1"; then
		echo "${new}" >> "$1"
	fi
}
{
	find "${DA_PATH}/data/users" -name commands.allow
	find "${DA_PATH}/data/users" -name commands.deny
	find "${DA_PATH}/data/templates/feature_sets" -name commands.allow
} | while IFS= read -r file; do
	add_command_alias_to_file "${file}" CMD_LOGIN_KEYS     login-keys
	add_command_alias_to_file "${file}" CMD_API_LOGIN_KEYS login-keys
	add_command_alias_to_file "${file}" CMD_SYSTEM_INFO    system-info
done
