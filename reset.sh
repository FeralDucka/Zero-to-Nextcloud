#!/bin/bash





# Check if the script is being run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root!" 1>&2
    exit 1
fi





#=============================================================================#
#                                                                             #
#                           CONFIGURATION  VARIABLES                          #
#                                                                             #
#=============================================================================#

NEXTCLOUD_USER="nc_user"
NEXTCLOUD_PASSWORD="password"

NEXTCLOUD_VERSION="latest"





#=============================================================================#
#                                                                             #
#                           MYSQL  DATABASE  RESET                            #
#                                                                             #
#=============================================================================#

mysql -u "$NEXTCLOUD_USER" -p"$NEXTCLOUD_PASSWORD" -e "DROP DATABASE IF EXISTS nextcloud;"





#=============================================================================#
#                                                                             #
#                           RESET  FILE  ATTRIBUTES                           #
#                                                                             #
#=============================================================================#

PHP_VERSION=$(php -v | grep '[1-9]\.[1-9]' -o -m 1)

chattr -i /etc/systemd/logind.conf
chattr -i /root/.profile
chattr -i /etc/nanorc
chattr -i /etc/sysctl.conf
chattr -i /usr/share/keymaps/keymap.map
chattr -i /etc/netplan/50-cloud-init.yaml
chattr -i /etc/chrony/chrony.conf
chattr -i /usr/local/sbin/backup_nextcloud_db.sh
chattr -i /usr/local/sbin/backup_nextcloud_www.sh
chattr -i /usr/local/sbin/check_nfs.sh
chattr -i /usr/local/sbin/check_ib.sh
chattr -i /usr/local/sbin/check_ip.sh
chattr -i /usr/local/sbin/check_service.sh
chattr -i /usr/local/sbin/ups_notify.sh
chattr -i /usr/local/sbin/telegram-send
chattr -i /etc/profile.d/login-notify.sh
chattr -i /etc/ssh/ssh_config
chattr -i /etc/ssh/sshd_config
chattr -i /etc/ufw/before.rules
chattr -i /etc/rsyslog.d/20-ufw.conf
chattr -i /etc/default/ufw
chattr -i /etc/fail2ban/fail2ban.conf
chattr -i /etc/fail2ban/jail.local
chattr -i /etc/fail2ban/action.d/telegram.conf
chattr -i /etc/fail2ban/scripts/telegram.sh
chattr -i /etc/nut/ups.conf
chattr -i /etc/nut/upsd.conf
chattr -i /etc/nut/nut.conf
chattr -i /etc/nut/upsmon.conf
chattr -i /etc/nut/upsd.users
chattr -i /etc/apache2/conf-available/other-vhosts-access-log.conf
chattr -i /etc/apache2/apache2.conf
chattr -i /etc/ssl/private/apache/apache-selfsigned.key
chattr -i /etc/ssl/certs/apache/apache-selfsigned.crt
chattr -i /etc/apache2/sites-available/nextcloud.conf
chattr -i /etc/modsecurity/modsecurity.conf
chattr -i /etc/apache2/mods-available/security2.conf
chattr -i /etc/apache2/mods-enabled/evasive.conf
chattr -i /etc/ssl/private/mysql/ssl-ca.key
chattr -i /etc/ssl/certs/mysql/ssl-ca.crt
chattr -i /etc/ssl/private/mysql/ssl-key.key
chattr -i /etc/ssl/certs/mysql/ssl-cert.crt
chattr -i /etc/mysql/my.cnf
chattr -i /etc/php/${PHP_VERSION}/fpm/php.ini
chattr -i /etc/php/${PHP_VERSION}/cli/php.ini
chattr -i /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
chattr -i /etc/php/${PHP_VERSION}/mods-available/apcu.ini
chattr -i /etc/php/${PHP_VERSION}/mods-available/igbinary.ini
chattr -i /etc/redis/redis.conf
chattr -i /etc/redis/redis.service

chmod 644 /etc/systemd/logind.conf
chmod 600 /root/.profile
chmod 644 /etc/nanorc
chmod 600 /etc/sysctl.conf
chmod 600 /usr/share/keymaps/keymap.map
chmod 600 /etc/netplan/50-cloud-init.yaml
chmod 600 /etc/chrony/chrony.conf
chmod 600 /usr/local/sbin/backup_nextcloud_db.sh
chmod 600 /usr/local/sbin/backup_nextcloud_www.sh
chmod 600 /usr/local/sbin/check_nfs.sh
chmod 600 /usr/local/sbin/check_ib.sh
chmod 600 /usr/local/sbin/check_ip.sh
chmod 600 /usr/local/sbin/check_service.sh
chmod 600 /usr/local/sbin/ups_notify.sh
chmod 600 /usr/local/sbin/telegram-send
chmod 600 /etc/profile.d/login-notify.sh
chmod 600 /etc/ssh/ssh_config
chmod 600 /etc/ssh/sshd_config
chmod 600 /etc/ufw/before.rules
chmod 600 /etc/rsyslog.d/20-ufw.conf
chmod 600 /etc/default/ufw
chmod 600 /etc/fail2ban/fail2ban.conf
chmod 600 /etc/fail2ban/jail.local
chmod 600 /etc/fail2ban/action.d/telegram.conf
chmod 600 /etc/fail2ban/scripts/telegram.sh
chmod 600 /etc/nut/ups.conf
chmod 600 /etc/nut/upsd.conf
chmod 600 /etc/nut/nut.conf
chmod 600 /etc/nut/upsmon.conf
chmod 600 /etc/nut/upsd.users
chmod 600 /etc/apache2/conf-available/other-vhosts-access-log.conf
chmod 600 /etc/apache2/apache2.conf
chmod 600 /etc/ssl/private/apache/apache-selfsigned.key
chmod 600 /etc/ssl/certs/apache/apache-selfsigned.crt
chmod 600 /etc/apache2/sites-available/nextcloud.conf
chmod 600 /etc/modsecurity/modsecurity.conf
chmod 600 /etc/apache2/mods-available/security2.conf
chmod 600 /etc/apache2/mods-enabled/evasive.conf
chmod 600 /etc/ssl/private/mysql/ssl-ca.key
chmod 600 /etc/ssl/certs/mysql/ssl-ca.crt
chmod 600 /etc/ssl/private/mysql/ssl-key.key
chmod 600 /etc/ssl/certs/mysql/ssl-cert.crt
chmod 600 /etc/mysql/my.cnf
chmod 600 /etc/php/${PHP_VERSION}/fpm/php.ini
chmod 600 /etc/php/${PHP_VERSION}/cli/php.ini
chmod 600 /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
chmod 600 /etc/php/${PHP_VERSION}/mods-available/apcu.ini
chmod 600 /etc/php/${PHP_VERSION}/mods-available/igbinary.ini
chmod 600 /etc/redis/redis.conf
chmod 600 /etc/redis/redis.service





#=============================================================================#
#                                                                             #
#                            DELETE  EXCESS  FILE                             #
#                                                                             #
#=============================================================================#

# The file will be re-genrated by setup.sh
rm /usr/local/sbin/telegram-send

# In case it was only partially unzipped, or the tar file was incomplete
rm /var/www/nextcloud
