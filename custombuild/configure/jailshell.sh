#!/bin/sh
#VERSION=0.10

#USER is already defined
#HOME is already defined
uid=$(id -u)
gid=$(id -g)
cp -a -u -f "/etc/exim.jail/${USER}.conf" "${HOME}/.msmtprc" 2>/dev/null
chmod 0400 "${HOME}/.msmtprc" 2>/dev/null
exec bwrap \
      --symlink      usr/bin                       /bin \
      --dev                                        /dev \
      --file         8                             /etc/passwd \
      --file         9                             /etc/group \
      --ro-bind-try  /etc/profile                  /etc/profile \
      --ro-bind-try  /etc/profile.d                /etc/profile.d \
      --ro-bind-try  /etc/bash.bashrc              /etc/bash.bashrc \
      --ro-bind-try  /etc/bashrc                   /etc/bashrc \
      --ro-bind-try  /etc/alternatives             /etc/alternatives \
      --ro-bind-try  /etc/localtime                /etc/localtime \
      --ro-bind-try  /etc/ld.so.cache              /etc/ld.so.cache \
      --ro-bind-try  /etc/resolv.conf              /etc/resolv.conf \
      --ro-bind-try  /etc/hosts                    /etc/hosts \
      --ro-bind-try  /etc/nsswitch.conf            /etc/nsswitch.conf \
      --ro-bind-try  /etc/ssl                      /etc/ssl \
      --ro-bind-try  /etc/pki                      /etc/pki \
      --ro-bind-try  /etc/man_db.conf              /etc/man_db.conf \
      --ro-bind-try  /etc/crypto-policies          /etc/crypto-policies \
      --bind        "${HOME}"                     "${HOME}" \
      --bind-try     /home/mysql/mysql.sock        /home/mysql/mysql.sock \
      --symlink      usr/lib                       /lib \
      --symlink      usr/lib64                     /lib64 \
      --proc                                       /proc \
      --bind-try    "/run/user/${uid}"            "/run/user/${uid}" \
      --symlink      usr/sbin                      /sbin \
      --tmpfs                                      /tmp \
      --bind-try     /tmp/mysql.sock               /tmp/mysql.sock \
      --bind-try     /var/lib/mysql/mysql.sock     /tmp/mysql.sock \
      --ro-bind      /usr                          /usr \
      --ro-bind-try  /usr/bin/msmtp                /usr/sbin/exim \
      --tmpfs                                      /usr/lib/modules \
      --tmpfs                                      /usr/lib/systemd \
      --dir                                        /var \
      --bind-try     /var/lib/mysql/mysql.sock     /var/lib/mysql/mysql.sock \
      --symlink      ../tmp                        /var/tmp \
      --remount-ro                                 / \
      --remount-ro                                 /usr/lib/modules \
      --remount-ro                                 /usr/lib/systemd \
      --unshare-all \
      --share-net \
      --die-with-parent \
      /bin/bash -l "$@" 8<<EOF 9<<EOF
${USER}:x:${uid}:${gid}::${HOME}:/usr/bin/jailshell
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
EOF
${USER}:x:${gid}:
nogroup:x:65534:
EOF
