#!/bin/bash
#VERSION=2.0.31
# This script is written by Martynas Bendorius and DirectAdmin
# It is used to create/renew let's encrypt certificate for a domain
# Official DirectAdmin webpage: http://www.directadmin.com
# Usage:
# ./letsencrypt.sh <domain> <key-size>
if [ "$(id -u)" != "0" ]; then
    echo "You require Root Access to run this script";
    exit 0
fi

export EXEC_PROPAGATION_TIMEOUT=300
export EXEC_POLLING_INTERVAL=30

LEGO=/usr/local/bin/lego

# Use Google DNS for external lookups
DNS_SERVER="8.8.8.8"
DNS6_SERVER="2001:4860:4860::8888"
# Fallback DNS server
NEW_IP="1.1.1.1"
NEW6_IP="2606:4700:4700::1111"
#NEW_IP=`cat /etc/resolv.conf |grep ^nameserver | grep -v 127.0.0.1 | head -n1 | cut -d\  -f2`
DA_IPV6=false

DNS_SERVERS=( "8.8.8.8" "1.1.1.1" "2001:4860:4860::8888" "2606:4700:4700::1111")

fallbackedDig(){
    lastret=1
    for i in "${DNS_SERVERS[@]}";do
        resp=$(${DIG} "@${i}" "$@")
        lastret=$?
        if [ "${lastret}" -eq "0" ];then
            echo "${resp}"
            return 0
        fi
        if [ "${lastret}" -ne "9" ];then
            return "${lastret}"
        fi
        DNS_SERVERS=("${DNS_SERVERS[@]:1}" "$i")
    done
    return ${lastret}
}



LEGO_DATA_PATH=/usr/local/directadmin/data/.lego

# Can be optionally passed as environment variables
staging=${staging:-}
dnsprovider=${dnsprovider:-}

if [ $# -lt 2 ]; then
    echo "Usage:"
    echo "    $0 request|request_single|request_full|renew|revoke <domain> <key-size> [<csr-config-file>] [<webroot-directory>]"
    echo ""
    echo "Got $# args:"
    echo "    $0 $1 $2 $3 $4 $5"
    echo ""
    echo "Multiple comma separated domains, owned by the same user, can be used for a certificate request"
    echo ""
    echo "Environment variables:"
    echo "    staging - if non empty LE staging env will be used"
    echo "    dnsprovider - passed to lego as DNS provider parameter"
    exit 0
elif [ $# -lt 3 ]; then
    #No key size specified, assign default one
    KEY_SIZE=ec256
fi
KEY_SIZE=$3
#Set key size (flag)
if [ "${KEY_SIZE}" = "secp384r1" ]; then
    KEY_SIZE="ec384"
elif [ "${KEY_SIZE}" = "prime256v1" ]; then
    KEY_SIZE="ec256"
elif [ "${KEY_SIZE}" = "4096" ]; then
    KEY_SIZE="rsa4096"
elif [ "${KEY_SIZE}" = "2048" ]; then
    KEY_SIZE="rsa2048"
elif [ "${KEY_SIZE}" = "8192" ]; then
    KEY_SIZE="rsa8192"
else
    #set default to ec256
    KEY_SIZE="ec256"
fi

DA_BIN="/usr/local/directadmin/directadmin"
if [ ! -s ${DA_BIN} ]; then
    echo "Unable to find DirectAdmin binary '${DA_BIN}'. Exiting..."
    exit 1
fi

#we received present/cleanup as $1 from lego callback
# ./letsencrypt.sh "present" "_acme-challenge.foo.example.com." "MsijOYZxqyjGnFGwhjrhfg-Xgbl5r68WPda0J9EgqqI"
if [ "$1" = "present" ]; then
    #remove _acme-challenge from the beginning
    DOMAIN_TO_USE=$(echo "$2" | perl -p0 -e 's|^_acme-challenge\.||g' | perl -p0 -e 's|\.$||g')
    # cleanup of the old record
    # it's run in reverse because the list is sorted for duplicates.  Must run the dataskq immediately before calling the add.
    ${DA_BIN} taskq --run "action=dns&do=delete&domain=${DOMAIN_TO_USE}&type=TXT&name=_acme-challenge"
    ${DA_BIN} taskq --run "action=dns&do=add&domain=${DOMAIN_TO_USE}&type=TXT&name=_acme-challenge&value=\"${3}\"&ttl=5&named_reload=yes"
    exit 0
elif [ "$1" = "cleanup" ]; then
    DOMAIN_TO_USE=$(echo "$2" | perl -p0 -e 's|^_acme-challenge\.||g' | perl -p0 -e 's|\.$||g')
    ${DA_BIN} taskq --run "action=dns&do=delete&domain=${DOMAIN_TO_USE}&type=TXT&name=_acme-challenge"
    exit 0
fi

if ${DA_BIN} c | grep -m1 -q "^ipv6=1$"; then
    if command -v ping6 > /dev/null; then
        if ping6 -q -c 1 -W 1 ${DNS6_SERVER} >/dev/null 2>&1; then
            DA_IPV6=true
            DNS_SERVER=${DNS6_SERVER}
            NEW_IP=${NEW6_IP}
        fi
    fi
fi

CURL=/usr/local/bin/curl
if [ ! -x ${CURL} ]; then
    CURL=/usr/bin/curl
fi

DIG=/usr/bin/dig
if [ ! -x ${DIG} ]; then
    if [ -x /usr/local/bin/dig ]; then
        DIG=/usr/local/bin/dig
    else
        echo "Cannot find $DIG nor /usr/local/bin/dig"
    fi
fi

CHALLENGETYPE="http"

GENERAL_TIMEOUT=40
CURL_OPTIONS=("--connect-timeout" "${GENERAL_TIMEOUT}" "-k" "--silent")

OPENSSL=/usr/bin/openssl
TIMESTAMP=$(date +%s)

ACCESS_GROUP_OPTION=$(${DA_BIN} c | grep '^secure_access_group=' | cut -d= -f2)
DA_HOSTNAME=$(${DA_BIN} c | grep '^servername=' | cut -d= -f2)
FILE_CHOWN="diradmin:mail"
FILE_CHMOD="640"
if [ "${ACCESS_GROUP_OPTION}" != "" ]; then
    FILE_CHOWN="diradmin:${ACCESS_GROUP_OPTION}"
fi

if [ ! -x ${LEGO} ]; then
    echo "${LEGO} is required, exiting..."
    exit 1
fi
####### PRE_CHECK FUNCTIONS BEGIN #########
DOCUMENT_ROOT=$5
WELLKNOWN_PATH="/var/www/html/.well-known/acme-challenge"
if [ -n "${DOCUMENT_ROOT}" ] && [ -d "${DOCUMENT_ROOT}" ]; then
    WELLKNOWN_PATH=${DOCUMENT_ROOT}
fi
caa_check() {
    CAA_OK=true
    for i in $(echo "$1" | awk -F'.' '{b=$NF;for(i=NF-1;i>0;i--){b=$i FS b;print b}}'); do
        if fallbackedDig CAA "${i}" +short | grep -m1 -q -F -- "issue"; then
            CAA_OK=false
            if fallbackedDig CAA "${i}" +short | grep -m1 -q -F -- "letsencrypt.org"; then
                CAA_OK=true
            else
                CAA_CURRENT=$(fallbackedDig CAA "${i}" +short | grep -m1 issue | awk '{print $3}')
            fi
        fi
        if fallbackedDig CAA "${i}" | grep -m1 -q -F -- "SERVFAIL"; then
            CAA_OK=false
            CAA_CURRENT="SERVFAIL"
        fi
    done

    if ! ${CAA_OK}; then
        echo "CAA record prevents issuing the certificate: ${CAA_CURRENT}"
        exit 1
    fi
}

challenge_check() {
    if [ ! -d "${WELLKNOWN_PATH}" ]; then
        mkdir -p "${WELLKNOWN_PATH}"
        chown "${USER}:${USER}" "${HOSTNAME_DIR}/.well-known"
        chown "${USER}:${USER}" "${WELLKNOWN_PATH}"
    fi
    RAND_BITS=$(openssl rand -hex 8)
    TEMP_FILENAME=letsencrypt_${TIMESTAMP}_${RAND_BITS}
    touch "${WELLKNOWN_PATH}/${TEMP_FILENAME}"
    chmod 644 "${WELLKNOWN_PATH}/${TEMP_FILENAME}"
    chown "${USER}:${USER}" "${WELLKNOWN_PATH}/${TEMP_FILENAME}"
    #if 8.8.8.8 is not accessible, dig returns code 9.  The dig|grep method returns code 1, so have to redo.
    IP_TO_RESOLV=$(fallbackedDig AAAA "$1" +short | grep -v '\.$' | tail -n1)
    if ! echo "${IP_TO_RESOLV}" | grep -m1 -q ':'; then
        IP_TO_RESOLV=""
    fi
    if [ -z "${IP_TO_RESOLV}" ]; then
        IP_TO_RESOLV=$(fallbackedDig "$1" +short | tail -n1)
    fi
    if [ -z "${IP_TO_RESOLV}" ]; then
        echo 1
        rm -f "${WELLKNOWN_PATH}/${TEMP_FILENAME}"
        return
    fi
    if command -v ping6 > /dev/null; then
        if ! ${DA_IPV6}; then
            if ! ping6 -q -c 1 -W 1 "$1" >/dev/null 2>&1; then
                IP_TO_RESOLV=$(fallbackedDig "$1" +short | tail -n1)
            fi
        fi
    fi
    if [ -n "${IP_TO_RESOLV}" ]; then
        if ${CURL} --help connection | grep -m1 -q 'resolve'; then
            CURL_OPTIONS+=("--resolve" "${1}:80:${IP_TO_RESOLV}" "--resolve" "${1}:443:${IP_TO_RESOLV}")
        fi
    fi
    if ! ${CURL} "${CURL_OPTIONS[@]}" -I -L -X GET "http://${1}/.well-known/acme-challenge/${TEMP_FILENAME}" 2>/dev/null | grep -m1 -q 'HTTP.*200'; then
        if [ "$2" = "silent" ]; then
            echo 1
            rm -f "${WELLKNOWN_PATH}/${TEMP_FILENAME}"
            return
        else
            echo "Challenge pre-checks for http://${1}/.well-known/acme-challenge/${TEMP_FILENAME} failed... Command:"
            echo "${CURL} ${CURL_OPTIONS[*]} -I -L -X GET http://${1}/.well-known/acme-challenge/${TEMP_FILENAME}"
            echo "Exiting."
            rm -f "${WELLKNOWN_PATH}/${TEMP_FILENAME}"
            exit 1
        fi
    elif [ "$2" = "silent" ]; then
        echo 0
        rm -f "${WELLKNOWN_PATH}/${TEMP_FILENAME}"
        return
    fi
    if [ -e "${WELLKNOWN_PATH}/${TEMP_FILENAME}" ]; then
        rm -f "${WELLKNOWN_PATH}/${TEMP_FILENAME}"
    fi
}
####### PRE_CHECK FUNCITONS END #########

#Set staging server if testing
SERVER_HOSTNAME=$(hostname -f 2>/dev/null)
if [ -z "${SERVER_HOSTNAME}" ] && [ -x /usr/bin/hostnamectl ]; then
    SERVER_HOSTNAME=$(/usr/bin/hostnamectl --static | head -n1)
    if ! echo "${SERVER_HOSTNAME}" | grep  -m1 -q '\.'; then
        SERVER_HOSTNAME=$(grep -m1 -o "${SERVER_HOSTNAME}\.[^ ]*" /etc/hosts)
    fi
fi
if [ ! -s /usr/local/directadmin/data/users/admin/user.conf ] ;then
    ADMIN_USERCONF=$(grep -l -m1 '^creator=root$' /usr/local/directadmin/data/users/*/user.conf)
    if [ -z "${ADMIN_USERCONF}" ]; then
        ADMIN_USERCONF="/usr/local/directadmin/data/users/$(head -n1 /usr/local/directadmin/data/admin/admin.list)/user.conf"
    fi
else
    ADMIN_USERCONF=/usr/local/directadmin/data/users/admin/user.conf
fi
if [ -n "${ADMIN_USERCONF}" ] && [ -s ${ADMIN_USERCONF} ]; then
    EMAIL=$(grep -m1 '^email=' ${ADMIN_USERCONF} 2>/dev/null | cut -d= -f2 | cut -d, -f1)
fi
if [ -z "${EMAIL}" ]; then
    EMAIL="admin@${SERVER_HOSTNAME}"
fi
DOMAIN=$2
CHILD_DOMAIN=false

#We want to spin lego webserver in case nothing listens on port 80
EXTERNAL_WEBSERVER=false
if (echo >/dev/tcp/localhost/80) &>/dev/null || (echo >"/dev/tcp/$(hostname)/80") &>/dev/null; then
    EXTERNAL_WEBSERVER=true
fi

#We need the domain to match in /etc/virtual/domainowners, if we use grep -F, we cannot use any regex'es including ^
FOUNDDOMAIN=0
for TDOMAIN in $(echo "${DOMAIN}" | tr ',' ' '); do
    if [ "${DA_HOSTNAME}" = "${TDOMAIN}" ]; then
        #we're a hostname, skip this check
        break
    fi
    DOMAIN_NAME_FOUND=${TDOMAIN}
    DOMAIN_ESCAPED=${TDOMAIN//./\\.}

    if grep -m1 -q "^${DOMAIN_ESCAPED}:" /etc/virtual/domainowners; then
        USER=$(grep -m1 "^${DOMAIN_ESCAPED}:" /etc/virtual/domainowners | cut -d' ' -f2)
        HOSTNAME=0
        FOUNDDOMAIN=1
        break
    fi
done

if [ "${FOUNDDOMAIN}" = "0" ]; then
    #check parent domain
    for TDOMAIN in $(echo "${DOMAIN}" | tr ',' ' '); do
        if [ "${DA_HOSTNAME}" = "${TDOMAIN}" ]; then
            #we're a hostname, skip this check
            break
        fi
        if [ "$(echo "${TDOMAIN}" | grep -o '\.' | wc -l)" -gt 1 ]; then
            CHILD_NAME=$(echo "${TDOMAIN}" | cut -d'.' -f1)
            PARENT_DOMAIN_NAME_FOUND=$(echo "${TDOMAIN}" | perl -p0 -e 's|^[^\.]*\.||g')
            PARENT_DOMAIN_ESCAPED=${PARENT_DOMAIN_NAME_FOUND//./\\.}
            PARENT_DOMAIN_OWNER_USER=$(grep -m1 "^${PARENT_DOMAIN_ESCAPED}:" /etc/virtual/domainowners | cut -d' ' -f2)
            if [ -s "/usr/local/directadmin/data/users/${PARENT_DOMAIN_OWNER_USER}/domains/${PARENT_DOMAIN_NAME_FOUND}.subdomains" ] && grep -q "^${CHILD_NAME}$" "/usr/local/directadmin/data/users/${PARENT_DOMAIN_OWNER_USER}/domains/${PARENT_DOMAIN_NAME_FOUND}.subdomains"; then
                DOMAIN_NAME_FOUND=${TDOMAIN}
                DOMAIN_ESCAPED=${DOMAIN_NAME_FOUND//./\\.}
                USER=${PARENT_DOMAIN_OWNER_USER}
                HOSTNAME=0
                FOUNDDOMAIN=1
                CHILD_DOMAIN=true
                break
            fi
        fi
    done
fi
if [ "${FOUNDDOMAIN}" = "0" ]; then
    LETSENCRYPT_LIST=$(${DA_BIN} c | grep -m1 "^letsencrypt_list=" | cut -d= -f2 | tr ':' ' ')
    #check parent domain
    for TDOMAIN in $(echo "${DOMAIN}" | tr ',' ' '); do
        if [ "${DA_HOSTNAME}" = "${TDOMAIN}" ]; then
            #we're a hostname, skip this check
            break
        fi
        if [ "${FOUNDDOMAIN}" != "0" ]; then
            break
        fi
        if [ "$(echo "${TDOMAIN}" | grep -o '\.' | wc -l)" -gt 1 ]; then
            CHILD_NAME=$(echo "${TDOMAIN}" | cut -d'.' -f1)
            PARENT_DOMAIN_NAME_FOUND=$(echo "${TDOMAIN}" | perl -p0 -e 's|^[^\.]*\.||g')
            PARENT_DOMAIN_ESCAPED=${PARENT_DOMAIN_NAME_FOUND//./\\.}
            PARENT_DOMAIN_OWNER_USER=$(grep -m1 "^${PARENT_DOMAIN_ESCAPED}:" /etc/virtual/domainowners | cut -d' ' -f2)
            for letsencrypt_prefix in ${LETSENCRYPT_LIST}; do
                if [ "${CHILD_NAME}" = "${letsencrypt_prefix}" ] && [ -n "${PARENT_DOMAIN_OWNER_USER}" ]; then
                    DOMAIN_NAME_FOUND=${TDOMAIN}
                    DOMAIN_ESCAPED=${DOMAIN_NAME_FOUND//./\\.}
                    USER=${PARENT_DOMAIN_OWNER_USER}
                    HOSTNAME=0
                    FOUNDDOMAIN=1
                    CHILD_DOMAIN=true
                    break
                fi
            done
        fi
    done
fi
if [ "${FOUNDDOMAIN}" = "0" ]; then
    for TDOMAIN in $(echo "${DOMAIN}" | tr ',' ' '); do
        DOMAIN_NAME_FOUND=${TDOMAIN}
        DOMAIN_ESCAPED=${DOMAIN_NAME_FOUND//./\\.}
        USER="root"
        if [ "${DA_HOSTNAME}" = "${TDOMAIN}" ]; then
            echo "Setting up certificate for a hostname: ${DOMAIN_NAME_FOUND}"
            HOSTNAME=1
            FOUNDDOMAIN=1
            if ! grep -m1 -q "^${DOMAIN_ESCAPED}$" /etc/virtual/domains; then
                echo "${DOMAIN_NAME_FOUND}" >> /etc/virtual/domains
            fi
            break
        else
            echo "Domain does not exist on the system. Unable to find ${DOMAIN_NAME_FOUND} in /etc/virtual/domainowners, and domain is not set as hostname (servername) in DirectAdmin configuration. Exiting..."
        fi
    done
fi

if [ ${FOUNDDOMAIN} -eq 0 ]; then
    echo "no valid domain found - exiting"
    exit 1
fi

CSR_CF_FILE=$4

DA_USERDIR="/usr/local/directadmin/data/users/${USER}"
DA_CONFDIR="/usr/local/directadmin/conf"
HOSTNAME_DIR="/var/www/html"

if [ ! -d "${DA_USERDIR}" ] && [ "${HOSTNAME}" -eq 0 ]; then
    echo "${DA_USERDIR} not found, exiting..."
    exit 1
elif [ ! -d "${DA_CONFDIR}" ] && [ "${HOSTNAME}" -eq 1 ]; then
    echo "${DA_CONFDIR} not found, exiting..."
    exit 1
fi

if [ "${HOSTNAME}" -eq 0 ]; then
    DNSPROVIDER_FALLBACK="${DA_USERDIR}/domains/${DOMAIN_NAME_FOUND}.dnsprovider"
    if [ -s "${DNSPROVIDER_FALLBACK}" ]; then
        if grep -m1 -q "^dnsprovider=inherit-creator$" "${DNSPROVIDER_FALLBACK}"; then
            CREATOR=$(grep -m1 '^creator=' "${DA_USERDIR}/user.conf" | cut -d= -f2)
            CREATOR_DNSPROVIDER="/usr/local/directadmin/data/users/${CREATOR}/dnsprovider.conf"
            if [ -s "${CREATOR_DNSPROVIDER}" ]; then
                    DNSPROVIDER_FALLBACK="${CREATOR_DNSPROVIDER}"
            fi
        elif grep -m1 -q "^dnsprovider=inherit-global$" "${DNSPROVIDER_FALLBACK}"; then
            if [ -s "/usr/local/directadmin/data/admin/dnsprovider.conf" ]; then
                DNSPROVIDER_FALLBACK="/usr/local/directadmin/data/admin/dnsprovider.conf"
            fi
        fi
    fi
    KEY="${DA_USERDIR}/domains/${DOMAIN_NAME_FOUND}.key"
    CERT="${DA_USERDIR}/domains/${DOMAIN_NAME_FOUND}.cert"
    CACERT="${DA_USERDIR}/domains/${DOMAIN_NAME_FOUND}.cacert"
    if [ "${DOCUMENT_ROOT}" != "" ]; then
        DOMAIN_DIR="${DOCUMENT_ROOT}"
    elif ${DA_BIN} c | grep -m1 -q '^letsencrypt=2$'; then
        USER_HOMEDIR=$(grep -m1 "^${USER}:" /etc/passwd | cut -d: -f6)
        DOMAIN_DIR="${USER_HOMEDIR}/domains/${DOMAIN_NAME_FOUND}/public_html"
    else
        DOMAIN_DIR="${HOSTNAME_DIR}"
    fi
    WELLKNOWN_PATH="${DOMAIN_DIR}/.well-known/acme-challenge"
else
    DNSPROVIDER_FALLBACK="${DA_CONFDIR}/ca.dnsprovider"
    KEY=$(${DA_BIN} c |grep ^cakey= | cut -d= -f2)
    CERT=$(${DA_BIN} c |grep ^cacert= | cut -d= -f2)
    CACERT=$(${DA_BIN} c |grep ^carootcert= | cut -d= -f2)
    SET_DA_CACERT=false
    if [ "${CACERT}" = "" ] || [ "${CERT}" = "${DA_CONFDIR}/carootcert.pem" ]; then
        CERT="${DA_CONFDIR}/cacert.pem"
        CACERT="${DA_CONFDIR}/carootcert.pem"
        SET_DA_CACERT=true
    fi
    DOMAIN_DIR="${HOSTNAME_DIR}"
    WELLKNOWN_PATH="${DOMAIN_DIR}/.well-known/acme-challenge"
fi

if [ -s "${CERT}" ] && [ "$1" = "renew" ]; then
    if [ -s "${CERT}" ]; then
        DOMAIN=$(${OPENSSL} x509 -text -noout -in "${CERT}" | grep -m1 'Subject Alternative Name:' -A1 | grep 'DNS:' | perl -p0 -e 's|DNS:||g' | tr -d ' ')
    fi
elif [ "$1" = "request" ] && ! echo "${DOMAIN}" | grep -m1 -q ","; then
    if [ -s "${CSR_CF_FILE}" ] && grep -m1 -q 'DNS:' "${CSR_CF_FILE}"; then
        DOMAIN=$(grep '^subjectAltName=' "${CSR_CF_FILE}" | cut -d= -f2 | grep 'DNS:' | perl -p0 -e 's|DNS:||g' | tr -d ' ')
    elif [ -s "${CERT}" ] && ${OPENSSL} x509 -text -noout -in "${CERT}" | grep -m1 -q 'Subject Alternative Name:' >/dev/null 2>&1; then
        DOMAIN=$(${OPENSSL} x509 -text -noout -in "${CERT}" | grep -m1 'Subject Alternative Name:' -A1 | grep 'DNS:' | perl -p0 -e 's|DNS:||g' | tr -d ' ')
    elif [ "${HOSTNAME}" -eq 0 ] && ! ${CHILD_DOMAIN}; then
        if ! echo "${DOMAIN}" | grep -q "^www\."; then
            #We have a domain without www., add www domain to to SAN too
            DOMAIN="${DOMAIN},www.${DOMAIN}"
        else
            #We have a domain with www., drop www and add it to SAN too
            DOMAIN2=$(echo "${DOMAIN}" | perl -p0 -e 's#^www.##')
            DOMAIN="${DOMAIN2},www.${DOMAIN2}"
        fi
    fi
elif [ "$1" = "request_full" ]; then
    #find all subdomains and pointers, and include them in the list.
    SUB_LIST_FILE="${DA_USERDIR}/domains/${DOMAIN}.subdomains"
    SUB_LIST=""

    if [ -s "${SUB_LIST_FILE}" ]; then
        SUB_LIST=$(cat "${SUB_LIST_FILE}")
    fi

    SUB_LIST="${SUB_LIST} www mail ftp smtp pop"
    for s in ${SUB_LIST}; do
        H=${s}.${DOMAIN}
        if [ "${CHALLENGETYPE}" = "http" ] && ${EXTERNAL_WEBSERVER}; then
            CHALLENGE_TEST=$(challenge_check "${H}" silent)
        else
            CHALLENGE_TEST=0
        fi
        if [ ${CHALLENGE_TEST} -eq 1 ] && [ "${CHALLENGETYPE}" = "http" ]; then
            echo "${H} was skipped due to unreachable http://${H}/.well-known/acme-challenge/${TEMP_FILENAME} file."
        else
            DOMAIN="${DOMAIN},${H}"
        fi
    done;

    POINTER_LIST="${DA_USERDIR}/domains/${DOMAIN}.pointers"
    if [ -s "${POINTER_LIST}" ]; then
        POINTERS=$(cut -d= -f1 "${POINTER_LIST}")
        for p in $POINTERS; do
                DOMAIN="${DOMAIN},${p},www.${p}"
        done;
    fi
fi

#It could be a symlink, so we use -e
if [ ! -e "${DOMAIN_DIR}" ]; then
    echo "${DOMAIN_DIR} does not exist. Exiting..."
    exit 1
fi

#Set validation method
CHALLENGETYPE=http
#empty env for dnsprovider - but dnsprovider file in use
if [ -s "${DNSPROVIDER_FALLBACK}" ] && [ -z "${dnsprovider}" ]; then
    readarray -t args < <(grep -o '^[a-zA-Z0-9_]*=[^;<>|\ ]*' "${DNSPROVIDER_FALLBACK}")
    export "${args[@]}"
fi
if [ -n "${dnsprovider}" ] && [ "${dnsprovider}" != "exec" ]; then
    echo "Found DNS provider configured: ${dnsprovider}"
    DNSPROVIDER_NAME=${dnsprovider}
    CHALLENGETYPE="dns"
elif echo "${DOMAIN}" | grep -m1 -q '\*\.'; then
    echo "Found wildcard domain name and http challenge type, switching to dns-01 validation."
    DNSPROVIDER_NAME="exec"
    CHALLENGETYPE="dns"
    export EXEC_PATH=/usr/local/directadmin/scripts/letsencrypt.sh
fi
if [ "${CHALLENGETYPE}" = "http" ]; then
    RESOLVING_DOMAINS=""
    for domain_name in $(echo "${DOMAIN}" | perl -p0 -e "s/,/ /g" | perl -p0 -e "s/^\*.//g"); do
        if ${EXTERNAL_WEBSERVER}; then
            CHALLENGE_TEST=$(challenge_check "${domain_name}" silent)
        else
            CHALLENGE_TEST=0
        fi
        if [ "${CHALLENGE_TEST}" -eq 1 ]; then
            echo "${domain_name} was skipped due to unreachable http://${domain_name}/.well-known/acme-challenge/${TEMP_FILENAME} file."
        else
            if [ -z "${RESOLVING_DOMAINS}" ]; then
                RESOLVING_DOMAINS="${domain_name}"
            else
                RESOLVING_DOMAINS="${RESOLVING_DOMAINS},${domain_name}"
            fi
        fi
    done
    if [ -z "${RESOLVING_DOMAINS}" ]; then
        echo "No domains pointing to this server to generate the certificate for."
        exit 1
    fi
    DOMAIN="${RESOLVING_DOMAINS}"
fi
#Run all domains through CAA and http pre-checks to save LE rate-limits
for domain_name in $(echo "${DOMAIN}" | perl -p0 -e "s/,/ /g" | perl -p0 -e "s/^\*.//g"); do
    caa_check "${domain_name}"
    if [ "${CHALLENGETYPE}" = "http" ] && ${EXTERNAL_WEBSERVER}; then
        challenge_check "${domain_name}"
    fi
done

FIRST_DOMAIN=$(echo "${DOMAIN}" | cut -d, -f1)
IFS=',' read -ra DOMAIN_ARRAY <<< "$DOMAIN"

# extract the acme_provider=provider from domain configuration and determine the ACME url from that
domain_conf_file="${DA_USERDIR}/domains/${FIRST_DOMAIN}.conf"
ACME=$(grep -m1 ^acme_provider= "${domain_conf_file}" 2>/dev/null | cut -d= -f2)

if [ "${ACME}" = "zerossl" ]; then
    API_URI="https://acme.zerossl.com/v2/DV90"
elif [ "${ACME}" = "letsencrypt" ] && [ "${staging}" = "yes" ]; then
    API_URI="https://acme-staging-v02.api.letsencrypt.org/directory"
elif [ "${ACME}" = "letsencrypt" ]; then
    API_URI="https://acme-v02.api.letsencrypt.org/directory"
elif [ -f /root/.zerossl ]; then
    API_URI="https://acme.zerossl.com/v2/DV90"
elif [ "${staging}" = "yes" ]; then
    API_URI="https://acme-staging-v02.api.letsencrypt.org/directory"
else
    API_URI="https://acme-v02.api.letsencrypt.org/directory"
fi

if [ "$1" = "request_single" ] || [ "$1" = "request" ] || [ "$1" = "renew" ] || [ "$1" = "request_full" ] ; then
    CERT_DOMAIN_FILE=$(echo "${FIRST_DOMAIN}" | tr '*' '_')
    LEGO_CERT_PATH="${LEGO_DATA_PATH}/certificates/${CERT_DOMAIN_FILE}.crt"
    LEGO_KEY_PATH="${LEGO_DATA_PATH}/certificates/${CERT_DOMAIN_FILE}.key"
    LEGO_ISSUER_CERT_PATH=$(echo "${LEGO_CERT_PATH}" | perl -p0 -e 's|\.crt$|.issuer.crt|g')
    if [ -s "${LEGO_KEY_PATH}" ] && [ -z "$3" ]; then
        if ! grep -m1 -q 'BEGIN EC PRIVATE' "${LEGO_KEY_PATH}"; then
            KEY_SIZE="rsa4096"
        fi
    fi
    LEGO_ARGS=(
        --path "${LEGO_DATA_PATH}"
        --dns.resolvers "${DNS_SERVER}"
        --accept-tos
        -s "${API_URI}"
        -m "${EMAIL}"
        --key-type "${KEY_SIZE}"
    )
    if [ "${CHALLENGETYPE}" = "http" ]; then
        LEGO_ARGS+=(--http)
        if ${EXTERNAL_WEBSERVER}; then
            LEGO_ARGS+=("--http.webroot" "${DOMAIN_DIR}")
        fi
    fi
    if [ "${CHALLENGETYPE}" = "dns" ]; then
        LEGO_ARGS+=(--dns "${DNSPROVIDER_NAME}")
    fi
    for d in "${DOMAIN_ARRAY[@]}"; do
        LEGO_ARGS+=(-d "$d")
    done
    if ${LEGO} "${LEGO_ARGS[@]}" run --no-bundle --preferred-chain="ISRG Root X1"; then
        if [ -s "${LEGO_CERT_PATH}" ] && [ -s "${LEGO_KEY_PATH}" ]; then
            if [ "$(grep -c "BEGIN CERTIFICATE" "${LEGO_CERT_PATH}")" -eq 1 ]; then
                cp -pf "${LEGO_CERT_PATH}" ${CERT}
            else
                ${OPENSSL} x509 -in "${LEGO_CERT_PATH}" -out ${CERT}
            fi
            cp -pf "${LEGO_KEY_PATH}" "${KEY}"
            if [ -s "${LEGO_ISSUER_CERT_PATH}" ]; then
                cp -pf "${LEGO_ISSUER_CERT_PATH}" ${CACERT}
                cat ${CERT} ${CACERT} > ${CERT}.combined
            else
                cp -pf "${LEGO_CERT_PATH}" ${CERT}.combined
            fi
            date +%s > ${CERT}.creation_time
            chown "${FILE_CHOWN}" "${KEY}" ${CERT} ${CERT}.combined ${CACERT} ${CERT}.creation_time
            chmod ${FILE_CHMOD} "${KEY}" ${CERT} ${CERT}.combined ${CACERT} ${CERT}.creation_time
            echo "Certificate for ${DOMAIN} has been created successfully!"
        else
            echo "New key/certificate is empty. Exiting..."
            exit 1
        fi
    else
        echo "Certificate generation failed."
        exit 1
    fi

    #Change exim, apache/nginx certs
    if [ "${HOSTNAME}" -eq 1 ]; then
        echo "DirectAdmin certificate has been setup."

        if grep -m1 -q "^cacert=${DA_CONFDIR}/carootcert.pem$" /usr/local/directadmin/conf/directadmin.conf; then
            ${DA_BIN} set cacert ${DA_CONFDIR}/cacert.pem
        fi
        if ${SET_DA_CACERT}; then
            ${DA_BIN} set carootcert "${CACERT}"
        fi
        if ${DA_BIN} c | grep -m1 -q "^ssl=0$"; then
            ${DA_BIN} set ssl 1
        fi

        #Exim
        echo "Setting up cert for Exim..."
        EXIMKEY="/etc/exim.key"
        EXIMCERT="/etc/exim.cert"
        cp -f "${KEY}" ${EXIMKEY}
        cat "${CERT}" "${CACERT}" > ${EXIMCERT}
        chown mail:mail ${EXIMKEY} ${EXIMCERT}
        chmod 600 ${EXIMKEY}
        chmod 644 ${EXIMCERT}

        ${DA_BIN} taskq --run "action=exim&value=restart"
        ${DA_BIN} taskq --run "action=dovecot&value=restart"

        #Apache
        echo "Setting up cert for WWW server..."
        if [ -d /etc/httpd/conf/ssl.key ] && [ -d /etc/httpd/conf/ssl.crt ]; then
            APACHEKEY="/etc/httpd/conf/ssl.key/server.key"
            APACHECERT="/etc/httpd/conf/ssl.crt/server.crt"
            APACHECACERT="/etc/httpd/conf/ssl.crt/server.ca"
            APACHECERTCOMBINED="${APACHECERT}.combined"
            cp -f "${KEY}" ${APACHEKEY}
            cp -f "${CERT}" ${APACHECERT}
            cp -f "${CACERT}" ${APACHECACERT}
            cat ${APACHECERT} ${APACHECACERT} > ${APACHECERTCOMBINED}
            chown root:root ${APACHEKEY} ${APACHECERT} ${APACHECACERT} ${APACHECERTCOMBINED}
            chmod 600 ${APACHEKEY} ${APACHECERT} ${APACHECACERT} ${APACHECERTCOMBINED}

            HTTPDACTION=restart
            GRACEFUL=$($DA_BIN c |grep ^graceful_restarts= | cut -d= -f2)
            if [ "$GRACEFUL" = "1" ]; then
                SYSTEMD=$($DA_BIN c |grep ^systemd= | cut -d= -f2)
                if [ "$SYSTEMD" = "1" ]; then
                    HTTPDACTION=reload
                else
                    HTTPDACTION=graceful
                fi
            fi

            ${DA_BIN} taskq --run "action=httpd&value=${HTTPDACTION}&affect_php_fpm=no"
        fi

        #Nginx
        if [ -d /etc/nginx/ssl.key ] && [ -d /etc/nginx/ssl.crt ]; then
            NGINXKEY="/etc/nginx/ssl.key/server.key"
            NGINXCERT="/etc/nginx/ssl.crt/server.crt"
            NGINXCACERT="/etc/nginx/ssl.crt/server.ca"
            NGINXCERTCOMBINED="${NGINXCERT}.combined"
            cp -f "${KEY}" ${NGINXKEY}
            cp -f "${CERT}" ${NGINXCERT}
            cp -f "${CACERT}" ${NGINXCACERT}
            cat ${NGINXCERT} ${NGINXCACERT} > ${NGINXCERTCOMBINED}
            chown root:root ${NGINXKEY} ${NGINXCERT} ${NGINXCACERT} ${NGINXCERTCOMBINED}
            chmod 600 ${NGINXKEY} ${NGINXCERT} ${NGINXCACERT} ${NGINXCERTCOMBINED}

            ${DA_BIN} taskq --run "action=nginx&value=restart&affect_php_fpm=no"
        fi

        #OLS
        if [ -d /usr/local/lsws/ssl.key ] && [ -d /usr/local/lsws/ssl.crt ]; then
            OLSKEY="/usr/local/lsws/ssl.key/server.key"
            OLSCERT="/usr/local/lsws/ssl.crt/server.crt"
            OLSCACERT="/usr/local/lsws/ssl.crt/server.ca"
            OLSCERTCOMBINED="${OLSCERT}.combined"
            cp -f "${KEY}" ${OLSKEY}
            cp -f "${CERT}" ${OLSCERT}
            cp -f "${CACERT}" ${OLSCACERT}
            cat ${OLSCERT} ${OLSCACERT} > ${OLSCERTCOMBINED}
            chown root:root ${OLSKEY} ${OLSCERT} ${OLSCACERT} ${OLSCERTCOMBINED}
            chmod 600 ${OLSKEY} ${OLSCERT} ${OLSCACERT} ${OLSCERTCOMBINED}

            ${DA_BIN} taskq --run "action=openlitespeed&value=restart&affect_php_fpm=no"
        fi

        #FTP
        echo "Setting up cert for FTP server..."
        cat "${KEY}" "${CERT}" "${CACERT}" > /etc/pure-ftpd.pem
        chmod 600 /etc/pure-ftpd.pem
        chown root:root /etc/pure-ftpd.pem

        if ${DA_BIN} c | grep -m1 -q "^pureftp=1\$"; then
            ${DA_BIN} taskq --run "action=pure-ftpd&value=restart"
        else
            ${DA_BIN} taskq --run "action=proftpd&value=restart"
        fi

        ${DA_BIN} taskq --run "action=directadmin&value=restart"
    fi
elif [ "$1" = "revoke" ]; then
    LEGO_ARGS=(
        --path "${LEGO_DATA_PATH}"
        -s "${API_URI}"
        -m "${EMAIL}"
    )
    for d in "${DOMAIN_ARRAY[@]}"; do
        LEGO_ARGS+=(-d "$d")
    done
    ${LEGO} "${LEGO_ARGS[@]}" revoke
fi
