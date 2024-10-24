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

REPO="https://raw.githubusercontent.com/FeralDucka/zero-to-nextcloud/main/files_to_copy/"

# -----------------------------------------------------------------------------#

HOST_USER="user"
HOST_PASSWORD="password"

ROOT_PASSWORD="password"

# -----------------------------------------------------------------------------#

NTP_SERVERS="0.it.pool.ntp.org 1.it.pool.ntp.org 2.it.pool.ntp.org"
TIMEZONE="Europe/Rome"

# -----------------------------------------------------------------------------#

TELEGRAM_KEY="xxxxxx"
TELEGRAM_CHAT_ID="xxxxxx"

# -----------------------------------------------------------------------------#

DUCKDNS_DOMAIN="xxxxxx"
DUCKDNS_TOKEN="xxxxxx"

# -----------------------------------------------------------------------------#

HOSTNAME="toaster.local"

# -----------------------------------------------------------------------------#

INFINIBAND_INTERFACE="ib1"

# -----------------------------------------------------------------------------#

NFS_IP="169.254.0.1"

# -----------------------------------------------------------------------------#

CERTBOT_MAIL="example@mail.com"

# -----------------------------------------------------------------------------#

MYSQL_PASSWORD="password"

# -----------------------------------------------------------------------------#

REDIS_PASSWORD="password"

# -----------------------------------------------------------------------------#

NEXTCLOUD_USER="nc_user"
NEXTCLOUD_PASSWORD="password"

# set minimum speed for Nextcloud download in Bytes/s
NEXTCLOUD_MIN_SPEED=$(echo "5 * 1024 * 1024" | bc)
NEXTCLOUD_VERSION="latest"

NEXTCLOUD_URL="example.org"
SERVER_IP="169.254.0.2"





#=============================================================================#
#                                                                             #
#                           SOFTWARE  INSTALLATION                            #
#                                                                             #
#=============================================================================#

# --- UPDATE and INSTALL ---
apt update
apt upgrade -y

# Installing required utilities
apt install -y bzip2 curl htop ffmpeg iputils-ping nano python3 wget

# Installing InfiniBand software
apt install -y infiniband-diags opensm

# Install tool needed to compile telegram-send-py
apt install -y binutils python3-venv

# Installing CRON
apt install -y cron

# Install SSH server
apt install -y openssh-server

# Installing Firewall software
apt install -y ufw

# Installing Fail2Ban software
apt install -y fail2ban

# Installing NFS software
apt install -y nfs-common

# Will respond to dialog box will appear for Postfix configuration, while installing libapache2-mod-evasive
echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections

# Installing Apache software
apt install -y apache2 apache2-utils libapache2-mod-evasive libapache2-mod-fcgid libapache2-mod-php libapache2-mod-security2

# Installing CertBot software
apt install -y libaugeas0

# Installing SQL server software
apt install -y mariadb-server

# Installing PHP software
apt install -y php php-fpm php-apcu php-bcmath php-bz2 php-curl php-gd php-gmp php-imagick php-intl php-mbstring php-mysql php-redis php-xml php-zip libmagickcore-6.q16-7-extra

# Get PHP version (will come useful in the script).
PHP_VERSION=$(php -v | grep '[1-9]\.[1-9]' -o -m 1)

# Installing Redis software
apt install -y redis-server

# Installin NUT software
apt install -y nut





#=============================================================================#
#                                                                             #
#                                HOMEKEEPING                                  #
#                                                                             #
#=============================================================================#

# Setting new strong password for default user and Root
chpasswd <<<"root:$ROOT_PASSWORD"
chpasswd <<<"$HOST_USER:$HOST_PASSWORD"

# -----------------------------------------------------------------------------#

# Removing default user from group
deluser $HOST_USER sudo

# -----------------------------------------------------------------------------#

# Setting NTP pools
sed -i "s|#NTP=|NTP=$NTP_SERVERS|" /etc/systemd/timesyncd.conf
systemctl restart systemd-timesyncd

# Setting Timezone
timedatectl set-timezone $TIMEZONE

# -----------------------------------------------------------------------------#

# Setting the Hostname of the machine
rm /etc/hostname
echo $HOSTNAME >> /etc/hostname

# -----------------------------------------------------------------------------#

# Setting up MOTD
rm -rf /etc/legal
chmod -x /etc/update-motd.d/10-help-text
chmod -x /etc/update-motd.d/50-motd-news
chmod -x /etc/update-motd.d/60-unminimize

# -----------------------------------------------------------------------------#

# -- Disabling showing system info when login as a normal user --
sed -i 's|^session[[:space:]]\+optional[[:space:]]\+pam_motd.so[[:space:]]\+motd=/run/motd.dynamic|#&|' /etc/pam.d/login
sed -i 's|^session[[:space:]]\+optional[[:space:]]\+pam_motd.so[[:space:]]\+noupdate|#&|' /etc/pam.d/login

sed -i 's|^session[[:space:]]\+optional[[:space:]]\+pam_motd.so[[:space:]]\+motd=/run/motd.dynamic|#&|' /etc/pam.d/sshd
sed -i 's|^session[[:space:]]\+optional[[:space:]]\+pam_motd.so[[:space:]]\+noupdate|#&|' /etc/pam.d/sshd

# -----------------------------------------------------------------------------#

# Showing MOTD and system status when login as "root"
rm /root/.profile
wget $REPO/HOMEKEEPING/.profile -O /root/.profile
chmod 500 /root/.profile

# -----------------------------------------------------------------------------#

# Set nano setting
rm /etc/nanorc
wget $REPO/NANO/nanorc -O /etc/nanorc





#=============================================================================#
#                                                                             #
#                             INFINIBAND  SETUP                               #
#                                                                             #
#=============================================================================#

# Download the file with the required InfiniBand modules
wget $REPO/INFINIBAND/infiniband.conf -O /etc/modules-load.d/infiniband.conf

# -----------------------------------------------------------------------------#

#Add cron job to set the InfiniBand interface in DATAGRAM mode (MTU: 65520)
crontab -u root -l | { cat; echo "@reboot echo connected > /sys/class/net/$INFINIBAND_INTERFACE/mode"; } | crontab -u root -

# -----------------------------------------------------------------------------#

# Load and enable modules instead without rebooting the host machine
MODULE_FILE="/etc/modules-load.d/infiniband.conf"
if [[ ! -f "$MODULE_FILE" ]]; then
    echo "Module file $MODULE_FILE not found!"
    exit 1
fi
while IFS= read -r module; do
    if [[ -z "$module" || "$module" =~ ^# ]]; then
        continue
    fi
    echo "Loading module: $module"
    modprobe "$module"
    if lsmod | grep -q "^$module"; then
        echo "$module loaded successfully"
    else
        echo "Failed to load $module"
    fi
done < "$MODULE_FILE"
echo "All modules processed."

# -----------------------------------------------------------------------------#

# Start OpenSM to load the InfiniBand interfaces (OpenSM will open automatically once rebooted)
opensm &
OPENSM_PID=$!
sleep 10
kill -SIGTERM $OPENSM_PID

# -----------------------------------------------------------------------------#

# Set InfiniBand interface in DATAGRAM mode (MTU: 65520)
echo connected > /sys/class/net/$INFINIBAND_INTERFACE/mode





#=============================================================================#
#                                                                             #
#                              NETWORK  SETUP                                 #
#                                                                             #
#=============================================================================#

# Remove auto-generated network settings
rm /etc/netplan/50-cloud-init.yaml

# Download new networking settings
wget $REPO/NETWORK/50-cloud-init.yaml -O /etc/netplan/50-cloud-init.yaml

# Only root can see the netplan
chmod 600 /etc/netplan/50-cloud-init.yaml
chattr +i /etc/netplan/50-cloud-init.yaml

# -----------------------------------------------------------------------------#

# Apply the new network settings
netplan apply

# -----------------------------------------------------------------------------#

# Set link up for needed interfaces
ip link set eth1 up
ip link set ib1 up

# -----------------------------------------------------------------------------#

# Refresh OpenSM to apply network settings on InfiniBand interfaces
opensm &
OPENSM_PID=$!
sleep 10
kill -SIGTERM $OPENSM_PID





#=============================================================================#
#                                                                             #
#                              UTILITY  SCRIPTS                               #
#                                                                             #
#=============================================================================#

# Download custom scripts
wget $REPO/SCRIPTS/check_nfs.sh -O /usr/local/sbin/check_nfs.sh
wget $REPO/SCRIPTS/check_ib.sh -O /usr/local/sbin/check_ib.sh
wget $REPO/SCRIPTS/check_ip.sh -O /usr/local/sbin/check_ip.sh
wget $REPO/SCRIPTS/check_service.sh -O /usr/local/sbin/check_service.sh
wget $REPO/SCRIPTS/telegram-send.py -O /usr/local/sbin/telegram-send.py
wget $REPO/SCRIPTS/login-notify.sh -O /etc/profile.d/login-notify.sh

# -----------------------------------------------------------------------------#

# Set up Telegram script with your credentials
sed -i "s|\[API_KEY\]|$TELEGRAM_KEY|" /usr/local/sbin/telegram-send.py
sed -i "s|\[CHAT_ID\]|$TELEGRAM_CHAT_ID|" /usr/local/sbin/telegram-send.py

# Compile Telegram Scrip into binary to mask credentials
python3 -m venv telegram_script_env
source telegram_script_env/bin/activate
pip install requests
pip install pyinstaller
pyinstaller --onefile --clean --hidden-import requests --distpath /usr/local/sbin/ /usr/local/sbin/telegram-send.py
deactivate
rm -rf build telegram_script_env telegram-send.spec
rm /usr/local/sbin/telegram-send.py

chmod 555 /usr/local/sbin/telegram-send
chattr +i /usr/local/sbin/telegram-send

# -----------------------------------------------------------------------------#

# Set up DuckDNS script with your credentials
sed -i "s|\[DOMAIN\]|$DUCKDNS_DOMAIN|" /usr/local/sbin/check_ip.sh
sed -i "s|\[TOKEN\]|$DUCKDNS_TOKEN|" /usr/local/sbin/check_ip.sh

# -----------------------------------------------------------------------------#

#  chmod only root can execute the files
chmod 500 /usr/local/sbin/check_nfs.sh
chmod 500 /usr/local/sbin/check_ib.sh
chmod 500 /usr/local/sbin/check_ip.sh
chmod 500 /usr/local/sbin/check_service.sh
chmod 555 /etc/profile.d/login-notify.sh

# -----------------------------------------------------------------------------#

# Make scripts immutable
chattr +i /usr/local/sbin/check_nfs.sh
chattr +i /usr/local/sbin/check_ib.sh
chattr +i /usr/local/sbin/check_ip.sh
chattr +i /usr/local/sbin/check_service.sh
chattr +i /etc/profile.d/login-notify.sh

# -----------------------------------------------------------------------------#

# Make folder for check_service.sh logs
mkdir /mnt/WEBSERVER_LOGS/services/

# -----------------------------------------------------------------------------#

# -- Add cronjob for checking scripts while server is running --
crontab -u root -l | { cat; echo "*/1 * * * * /usr/local/sbin/check_ib.sh"; } | crontab -u root -
crontab -u root -l | { cat; echo "*/5 * * * * /usr/local/sbin/check_ip.sh"; } | crontab -u root -
crontab -u root -l | { cat; echo "*/1 * * * * /usr/local/sbin/check_service.sh apache2"; } | crontab -u root -
crontab -u root -l | { cat; echo "*/1 * * * * /usr/local/sbin/check_service.sh mysql"; } | crontab -u root -
crontab -u root -l | { cat; echo "*/1 * * * * /usr/local/sbin/check_service.sh php$PHP_VERSION-fpm"; } | crontab -u root -
crontab -u root -l | { cat; echo "*/1 * * * * /usr/local/sbin/check_service.sh redis"; } | crontab -u root -

# -----------------------------------------------------------------------------#

# -- Add cronjob for checking scripts at reboot --
crontab -u root -l | { cat; echo "@reboot /usr/local/sbin/check_ib.sh"; } | crontab -u root -
crontab -u root -l | { cat; echo "@reboot /usr/local/sbin/check_ip.sh"; } | crontab -u root -
crontab -u root -l | { cat; echo "@reboot /usr/local/sbin/check_service.sh apache2"; } | crontab -u root -
crontab -u root -l | { cat; echo "@reboot /usr/local/sbin/check_service.sh mysql"; } | crontab -u root -
crontab -u root -l | { cat; echo "@reboot /usr/local/sbin/check_service.sh php$PHP_VERSION-fpm"; } | crontab -u root -
crontab -u root -l | { cat; echo "@reboot /usr/local/sbin/check_service.sh redis"; } | crontab -u root -





#=============================================================================#
#                                                                             #
#                              FOLDERS  SETUP                                 #
#                                                                             #
#=============================================================================#

# create require folders for Nextcloud and monitoring
mkdir /mnt/NEXTCLOUD_BACKUP
mkdir /mnt/NEXTCLOUD_CACHE
mkdir /mnt/NEXTCLOUD_DATA
mkdir /mnt/NEXTCLOUD_LOGS
mkdir /mnt/WEBSERVER_LOGS

# -----------------------------------------------------------------------------#

# Make the folder own by www-data
chown -R www-data:www-data /mnt/NEXTCLOUD_BACKUP
chown -R www-data:www-data /mnt/NEXTCLOUD_CACHE
chown -R www-data:www-data /mnt/NEXTCLOUD_DATA
chown -R www-data:www-data /mnt/NEXTCLOUD_LOGS
chown -R root:root /mnt/WEBSERVER_LOGS

# -----------------------------------------------------------------------------#

# Mount the NFS folders
/usr/local/sbin/check_nfs.sh $NFS_IP NEXTCLOUD_BACKUP
/usr/local/sbin/check_nfs.sh $NFS_IP NEXTCLOUD_DATA
/usr/local/sbin/check_nfs.sh $NFS_IP NEXTCLOUD_LOGS
/usr/local/sbin/check_nfs.sh $NFS_IP WEBSERVER_LOGS

# -----------------------------------------------------------------------------#

# Add cronjobs for checking if the NFS folders are mounted
crontab -u root -l | { cat; echo "*/1 * * * * /usr/local/sbin/check_nfs.sh $NFS_IP NEXTCLOUD_BACKUP"; } | crontab -u root -
crontab -u root -l | { cat; echo "*/1 * * * * /usr/local/sbin/check_nfs.sh $NFS_IP NEXTCLOUD_DATA"; } | crontab -u root -
crontab -u root -l | { cat; echo "*/1 * * * * /usr/local/sbin/check_nfs.sh $NFS_IP NEXTCLOUD_LOGS"; } | crontab -u root -
crontab -u root -l | { cat; echo "*/1 * * * * /usr/local/sbin/check_nfs.sh $NFS_IP WEBSERVER_LOGS"; } | crontab -u root -

# -----------------------------------------------------------------------------#

# Add cronjobs for mounting the NFS folders at reboot
crontab -u root -l | { cat; echo "@reboot /usr/local/sbin/check_nfs.sh $NFS_IP NEXTCLOUD_BACKUP"; } | crontab -u root -
crontab -u root -l | { cat; echo "@reboot /usr/local/sbin/check_nfs.sh $NFS_IP NEXTCLOUD_DATA"; } | crontab -u root -
crontab -u root -l | { cat; echo "@reboot /usr/local/sbin/check_nfs.sh $NFS_IP NEXTCLOUD_LOGS"; } | crontab -u root -
crontab -u root -l | { cat; echo "@reboot /usr/local/sbin/check_nfs.sh $NFS_IP WEBSERVER_LOGS"; } | crontab -u root -





#=============================================================================#
#                                                                             #
#                                 SSH  SETUP                                  #
#                                                                             #
#=============================================================================#

rm /etc/ssh/ssh_config
wget $REPO/SSH/ssh_config -O /etc/ssh/ssh_config
chmod 400 /etc/ssh/ssh_config
chattr +i /etc/ssh/ssh_config

# -----------------------------------------------------------------------------#

rm /etc/ssh/sshd_config
wget $REPO/SSH/sshd_config -O /etc/ssh/sshd_config
chmod 400 /etc/ssh/sshd_config
chattr +i /etc/ssh/sshd_config

# -----------------------------------------------------------------------------#

systemctl enable ssh
systemctl restart ssh





#=============================================================================#
#                                                                             #
#                              FIREWALL  SETUP                                #
#                                                                             #
#=============================================================================#

rm /etc/ufw/before.rules
wget $REPO/UFW/before.rules -O /etc/ufw/before.rules

# -----------------------------------------------------------------------------#

ufw default deny incoming
ufw default deny outgoing

# -----------------------------------------------------------------------------#

ufw allow in on eth4 to any port 22 proto tcp         # For SSH connection
ufw allow out on eth1 to any port 53 proto tcp        # For DNS queries
ufw allow in on eth1 to any port 80 proto tcp         # For HTTP Nextcloud
ufw allow out on eth1 to any port 80 proto tcp        # For apt update
ufw allow out on eth1 to any port 53 proto udp        # For NTP client
ufw allow in on eth1 to any port 443 proto tcp        # For HTTPS Nextcloud
ufw allow out on eth1 to any port 443 proto tcp       # For Telegram script / wget GitHub
ufw allow in on ib1 to any port 2049                  # For NFS
ufw allow out on ib1 to any port 2049                 # For NFS
ufw allow in on ib1 to any port 3493 proto tcp        # For NUT

# -----------------------------------------------------------------------------#

ufw logging high

# -----------------------------------------------------------------------------#

echo "y" | ufw enable





#=============================================================================#
#                                                                             #
#                              FAIL2BAN  SETUP                                #
#                                                                             #
#=============================================================================#

mkdir /etc/fail2ban/scripts/

# -----------------------------------------------------------------------------#

wget $REPO/FAIL2BAN/fail2ban.conf -O /etc/fail2ban/fail2ban.conf
wget $REPO/FAIL2BAN/jail.local -O /etc/fail2ban/jail.local
wget $REPO/FAIL2BAN/telegram.conf -O /etc/fail2ban/action.d/telegram.conf
wget $REPO/FAIL2BAN/telegram.sh -O /etc/fail2ban/scripts/telegram.sh

# -----------------------------------------------------------------------------#

chmod 400 /etc/fail2ban/fail2ban.conf
chmod 400 /etc/fail2ban/jail.local
chmod 400 /etc/fail2ban/action.d/telegram.conf
chmod 400 /etc/fail2ban/scripts/telegram.sh

# -----------------------------------------------------------------------------#

chattr +i /etc/fail2ban/fail2ban.conf
chattr +i /etc/fail2ban/jail.local
chattr +i /etc/fail2ban/action.d/telegram.conf
chattr +i /etc/fail2ban/scripts/telegram.sh

# -----------------------------------------------------------------------------#

systemctl enable fail2ban
systemctl start fail2ban





#=============================================================================#
#                                                                             #
#                                NUT  SETUP                                   #
#                                                                             #
#=============================================================================#

rm /etc/nut/ups.conf
rm /etc/nut/upsd.conf
rm /etc/nut/nut.conf
rm /etc/nut/upsd.users

# -----------------------------------------------------------------------------#

wget $REPO/NUT/ups.conf -O /etc/nut/ups.conf
wget $REPO/NUT/upsd.conf -O /etc/nut/upsd.conf
wget $REPO/NUT/nut.conf -O /etc/nut/nut.conf
wget $REPO/NUT/upsd.users -O /etc/nut/upsd.users

# -----------------------------------------------------------------------------#

chown nut /etc/nut/ups.conf
chown nut /etc/nut/upsd.conf
chown nut /etc/nut/nut.conf
chown nut /etc/nut/upsd.users

# -----------------------------------------------------------------------------#

sudo -u nut chmod 400 /etc/nut/ups.conf
sudo -u nut chmod 400 /etc/nut/upsd.conf
sudo -u nut chmod 400 /etc/nut/nut.conf
sudo -u nut chmod 400 /etc/nut/upsd.users

# -----------------------------------------------------------------------------#

chattr +i /etc/nut/ups.conf
chattr +i /etc/nut/upsd.conf
chattr +i /etc/nut/nut.conf
chattr +i /etc/nut/upsd.users

# -----------------------------------------------------------------------------#

systemctl restart nut-server.service
systemctl restart nut-client.service





#=============================================================================#
#                                                                             #
#                               APACHE  SETUP                                 #
#                                                                             #
#=============================================================================#

# Create folder for the logs of Apache
mkdir /mnt/WEBSERVER_LOGS/apache
chown www-data:www-data /mnt/WEBSERVER_LOGS/apache
rm -rf /var/log/apache2

# -----------------------------------------------------------------------------#

# Configure other vHosts log file path
rm /etc/apache2/conf-available/other-vhosts-access-log.conf
wget $REPO/APACHE/other-vhosts-access-log.conf -O /etc/apache2/conf-available/other-vhosts-access-log.conf
chmod 644 /etc/apache2/conf-available/other-vhosts-access-log.conf
chattr +i /etc/apache2/conf-available/other-vhosts-access-log.conf

# -----------------------------------------------------------------------------#

# Copy new Apache2 configurations
rm /etc/apache2/apache2.conf
wget $REPO/APACHE/apache2.conf -O /etc/apache2/apache2.conf
chattr +i /etc/apache2/apache2.conf

# -----------------------------------------------------------------------------#

FPM_CONF=$(ls /etc/apache2/conf-available/ | grep -E 'php.+-fpm' | awk -F '.conf' '{print $1}')

# Enable PHP-FPM modules
a2dismod php${PHP_VERSION}
a2dismod mpm_prefork
a2enmod mpm_event
a2enmod proxy
a2enmod proxy_fcgi
a2enmod setenvif
a2enconf ${FPM_CONF}

# Enable HTTP/2 module
a2enmod http2

# Enable modsecurity2 modules
a2enmod security2
a2enmod unique_id

# Enable Nextcloud required modules
a2enmod dir
a2enmod env
a2enmod headers
a2enmod mime
a2enmod rewrite
a2enmod setenvif
a2enmod ssl

# -----------------------------------------------------------------------------#

# -- SSL folders for Apache --
mkdir /etc/ssl/certs/apache
mkdir /etc/ssl/private/apache

chown www-data:www-data /etc/ssl/certs/apache
chown www-data:www-data /etc/ssl/private/apache

# The files that will be generated
APACHE_CA_KEY="/etc/ssl/private/apache/apache-selfsigned.key"
APACHE_CA_CRT="/etc/ssl/certs/apache/apache-selfsigned.crt"

#Generate self-signed certificates for HTTPS
openssl genrsa -out "$APACHE_CA_KEY" 4096
openssl req -x509 -new -nodes -key "$APACHE_CA_KEY" -sha256 -days 3650 -out "$APACHE_CA_CRT" -subj "/C=IT/ST=State/L=City/O=Organization/OU=Department/CN=apacheCA"

# -- Make www-data own the files
chown www-data:www-data $APACHE_CA_KEY
chown www-data:www-data $APACHE_CA_CRT

# Lock the files
sudo -u www-data chmod 400 $APACHE_CA_KEY
sudo -u www-data chmod 400 $APACHE_CA_CRT

chattr +i $APACHE_CA_KEY
chattr +i $APACHE_CA_CRT

# -----------------------------------------------------------------------------#

# Remove default website
a2dissite 000-default.conf
rm /etc/apache2/sites-available/000-default.conf
rm -rf /var/www/html

# -----------------------------------------------------------------------------#

# Download and enable Nextcloud VirtualHost
wget $REPO/APACHE/nextcloud.conf -O /etc/apache2/sites-available/nextcloud.conf
sed -i "s|\[TLD\]|$NEXTCLOUD_URL|" /etc/apache2/sites-available/nextcloud.conf
chmod 400 /etc/apache2/sites-available/nextcloud.conf
chattr +i /etc/apache2/sites-available/nextcloud.conf
a2ensite nextcloud.conf

# -----------------------------------------------------------------------------#

systemctl enable apache2
systemctl restart apache2





#=============================================================================#
#                                                                             #
#                            MODSECURITY  SETUP                               #
#                                                                             #
#=============================================================================#

# Create folder for the logs of ModSecurity
mkdir /mnt/WEBSERVER_LOGS/apache/modsec
chown www-data:www-data /mnt/WEBSERVER_LOGS/apache/modsec

# -----------------------------------------------------------------------------#

# ModSecurity.conf configuration
rm /etc/modsecurity/modsecurity.conf
wget $REPO/MODSECURITY/modsecurity.conf -O /etc/modsecurity/modsecurity.conf
chmod 400 /etc/modsecurity/modsecurity.conf
chattr +i /etc/modsecurity/modsecurity.conf

# -----------------------------------------------------------------------------#

mkdir /etc/modsecuirty/plugins
mkdir /etc/modsecuirty/rules

# -----------------------------------------------------------------------------#

# ModSecurity Apache2 module configuration
rm /etc/apache2/mods-available/security2.conf
wget $REPO/MODSECURITY/security2.conf -O /etc/apache2/mods-available/security2.conf
chmod 400 /etc/apache2/mods-available/security2.conf
chattr +i /etc/apache2/mods-available/security2.conf

# -----------------------------------------------------------------------------#

# Download latest version of OWAS Core Rule Set (CRS)
VER=$(curl --silent -qI https://github.com/coreruleset/coreruleset/releases/latest | awk -F '/' '/^location/ {print  substr($NF, 1, length($NF)-1)}')
wget https://github.com/coreruleset/coreruleset/releases/download/$VER/coreruleset-${VER#v}-minimal.tar.gz -P /etc/modsecurity/
tar xvf /etc/modsecurity/coreruleset-${VER#v}-minimal.tar.gz -C /etc/modsecurity/
rm /etc/modsecurity/coreruleset-${VER#v}-minimal.tar.gz

# -----------------------------------------------------------------------------#

# Copying the needed files to the right location
mv -f /etc/modsecurity/coreruleset-${VER#v}/rules/* /etc/modsecurity/rulse/
mv -f /etc/modsecurity/coreruleset-${VER#v}/crs-setup.conf.example /etc/modsecurity/crs/

# -----------------------------------------------------------------------------#

# Removing leftover folders
rm /etc/modsecurity/coreruleset-${VER#v}

# -----------------------------------------------------------------------------#

systemctl restart apache2





#=============================================================================#
#                                                                             #
#                             MODEVASIVE  SETUP                               #
#                                                                             #
#=============================================================================#

# Create folder for the logs of ModSecurity
mkdir /mnt/WEBSERVER_LOGS/apache/modevasive
chown www-data:www-data /mnt/WEBSERVER_LOGS/apache/modevasive

# -----------------------------------------------------------------------------#

rm /etc/apache2/mods-available/evasive.conf
wget $REPO/MODEVASIVE/evasive.conf -O /etc/apache2/mods-available/evasive.conf
chmod 400 /etc/apache2/mods-enabled/evasive.conf
chattr +i /etc/apache2/mods-enabled/evasive.conf

# -----------------------------------------------------------------------------#

systemctl restart apache2





#=============================================================================#
#                                                                             #
#                               CERTBOT  SETUP                                #
#                                                                             #
#=============================================================================#

# Enable editing of the Virtual Host file
chattr -i /etc/apache2/sites-available/nextcloud.conf
sudo -u www-data chmod 666 /etc/apache2/sites-available/nextcloud.conf

# -----------------------------------------------------------------------------#

# Setup python virtual enviroment
python3 -m venv /opt/certbot/
/opt/certbot/bin/pip install --upgrade pip

# Install CertBot
/opt/certbot/bin/pip install certbot certbot-apache

# Prepare CertBor command
ln -s /opt/certbot/bin/certbot /usr/bin/certbot

# Install certificates
certbot -m $CERTBOT_MAIL  --non-interactive --agree-tos --apache --domain $NEXTCLOUD_URL

# -----------------------------------------------------------------------------#

# Lock the Virtual Host file
sudo -u www-data chmod 400 /etc/apache2/sites-available/nextcloud.conf
chattr +i /etc/apache2/sites-available/nextcloud.conf

# -----------------------------------------------------------------------------#

systemctl restart apache2





#=============================================================================#
#                                                                             #
#                                MYSQL  SETUP                                 #
#                                                                             #
#=============================================================================#

# Create folder for the logs of MariaDB
mkdir /mnt/WEBSERVER_LOGS/mysql
chown mysql:mysql /mnt/WEBSERVER_LOGS/mysql

# -----------------------------------------------------------------------------#

# Define the names for the certificate files
MYSQL_CA_KEY="/etc/ssl/private/mysql/ssl-ca.key"
MYSQL_CA_CRT="/etc/ssl/certs/mysql/ssl-ca.crt"
MYSQL_SERVER_KEY="/etc/ssl/private/mysql/ssl-key.key"
MYSQL_SERVER_CRT="/etc/ssl/certs/mysql/ssl-cert.crt"
MYSQL_SERVER_CSR="/tmp/mysql_server.csr"

mkdir /etc/ssl/certs/mysql
mkdir /etc/ssl/private/mysql

chown mysql:mysql /etc/ssl/certs/mysql
chown /etc/ssl/private/mysql

# -----------------------------------------------------------------------------#

# -- Generate needed SSL files for MySQL server --

# Step 1: Generate CA Key and Certificate
echo "Generating Certificate Authority (CA) Key and Certificate..."
openssl genrsa -out "$MYSQL_CA_KEY" 4096
openssl req -x509 -new -nodes -key "$MYSQL_CA_KEY" -sha256 -days 3650 -out "$MYSQL_CA_CRT" -subj "/C=IT/ST=State/L=City/O=Organization/OU=Department/CN=mysqlCA"

# Step 2: Generate Server Key
echo "Generating Server Key..."
openssl genrsa -out "$MYSQL_SERVER_KEY" 4096

# Step 3: Generate Certificate Signing Request (CSR) for the Server
echo "Generating Certificate Signing Request (CSR) for the Server..."
openssl req -new -key "$MYSQL_SERVER_KEY" -out "$MYSQL_SERVER_CSR" -subj "/C=IT/ST=State/L=City/O=Organization/OU=Department/CN=$NEXTCLOUD_URL"

# Step 4: Generate Server Certificate signed by the CA
echo "Generating Server Certificate signed by the CA..."
openssl x509 -req -in "$MYSQL_SERVER_CSR" -CA "$MYSQL_CA_CRT" -CAkey "$MYSQL_CA_KEY" -CAcreateserial -out "$MYSQL_SERVER_CRT" -days 365 -sha256

# Cleanup CSR
rm "$MYSQL_SERVER_CSR"

# -----------------------------------------------------------------------------#

# Make user mysql own the files
chown mysql:mysql $MYSQL_CA_KEY
chown mysql:mysql $MYSQL_CA_CRT
chown mysql:mysql $MYSQL_SERVER_KEY
chown mysql:mysql $MYSQL_SERVER_CRT

# -----------------------------------------------------------------------------#

sudo -u mysql chmod 400 $MYSQL_CA_KEY
sudo -u mysql chmod 400 $MYSQL_CA_CRT
sudo -u mysql chmod 400 $MYSQL_SERVER_KEY
sudo -u mysql chmod 400 $MYSQL_SERVER_CRT

# -----------------------------------------------------------------------------#

chattr +i $MYSQL_CA_KEY
chattr +i $MYSQL_CA_CRT
chattr +i $MYSQL_SERVER_KEY
chattr +i $MYSQL_SERVER_CRT

# -----------------------------------------------------------------------------#

# Copy New mySQL configurations
rm /etc/mysql/my.cnf
wget $REPO/MYSQL/my.cnf -O /etc/mysql/my.cnf
chattr +i /etc/mysql/my.cnf

# -----------------------------------------------------------------------------#

# Modify /etc/security/limits.conf
wget -O - $REPO/MYSQL/limits.conf >> /etc/security/limits.conf
echo >> /etc/security/limits.conf

# -----------------------------------------------------------------------------#

# Equivalent of mysql_secure_installation
mysql -e "UPDATE mysql.global_priv SET priv=json_set(priv, '$.password_last_changed', UNIX_TIMESTAMP(), '$.plugin', 'mysql_native_password', '$.authentication_string', 'invalid', '$.auth_or', json_array(json_object(), json_object('plugin', 'unix_socket'))) WHERE User='root';"
mysql -e "UPDATE mysql.global_priv SET priv=json_set(priv, '$.plugin', 'mysql_native_password', '$.authentication_string', PASSWORD('$MYSQL_PASSWORD')) WHERE User='root';"
mysql -e "DELETE FROM mysql.global_priv WHERE User='';"
mysql -e "DELETE FROM mysql.global_priv WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
mysql -e "DROP DATABASE IF EXISTS test;"
mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%'"
mysql -e "FLUSH PRIVILEGES;"

# -----------------------------------------------------------------------------#

# Add required database for Nextcloud
mysql --user root --password="${MYSQL_PASSWORD}" -e "CREATE DATABASE nextcloud CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;"
mysql --user root --password="${MYSQL_PASSWORD}" -e "CREATE USER '${NEXTCLOUD_USER}'@'localhost' identified by '${NEXTCLOUD_PASSWORD}';"
mysql --user root --password="${MYSQL_PASSWORD}" -e "GRANT ALL PRIVILEGES on nextcloud.* to '${NEXTCLOUD_USER}'@'localhost';"
mysql --user root --password="${MYSQL_PASSWORD}" -e "FLUSH PRIVILEGES;"

# -----------------------------------------------------------------------------#

systemctl enable mysql
systemctl restart mysql





#=============================================================================#
#                                                                             #
#                                 PHP  SETUP                                  #
#                                                                             #
#=============================================================================#

# Create folder for the logs of PHP
mkdir /mnt/WEBSERVER_LOGS/php
chown www-data:www-data /mnt/WEBSERVER_LOGS/php
rm /var/log/php${PHP_VERSION}-fpm.log

# -----------------------------------------------------------------------------#

# -- Config php.ini --
rm /etc/php/${PHP_VERSION}/fpm/php.ini
wget $REPO/PHP/fpm_php.ini -O /etc/php/${PHP_VERSION}/fpm/php.ini
chattr +i /etc/php/${PHP_VERSION}/fpm/php.ini

rm /etc/php/${PHP_VERSION}/cli/php.ini
wget $REPO/PHP/cli_php.ini -O /etc/php/${PHP_VERSION}/cli/php.ini
chattr +i /etc/php/${PHP_VERSION}/cli/php.ini

# -----------------------------------------------------------------------------#

# FPM parameters
rm /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
wget $REPO/PHP/www.conf -O /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf
chattr +i /etc/php/${PHP_VERSION}/fpm/pool.d/www.conf

# -----------------------------------------------------------------------------#

# APCu config
rm /etc/php/${PHP_VERSION}/mods-available/apcu.ini
wget $REPO/PHP/apcu.ini -O /etc/php/${PHP_VERSION}/mods-available/apcu.ini
chmod 644 /etc/php/${PHP_VERSION}/mods-available/apcu.ini
chattr +i /etc/php/${PHP_VERSION}/mods-available/apcu.ini


# -----------------------------------------------------------------------------#

# igbinary config
rm /etc/php/${PHP_VERSION}/mods-available/igbinary.ini
wget $REPO/PHP/igbinary.ini -O /etc/php/${PHP_VERSION}/mods-available/igbinary.ini
chmod 644 /etc/php/${PHP_VERSION}/mods-available/igbinary.ini
chattr +i /etc/php/${PHP_VERSION}/mods-available/igbinary.ini

# -----------------------------------------------------------------------------#

# Enable PHP modules required by Nextcloud
phpenmod apcu
phpenmod igbinary
phpenmod imagick
phpenmod redis

# -----------------------------------------------------------------------------#

systemctl enable php$PHP_VERSION-fpm
systemctl restart php$PHP_VERSION-fpm





#=============================================================================#
#                                                                             #
#                                REDIS  SETUP                                 #
#                                                                             #
#=============================================================================#

# Stop redis to avoid error while change the configuration
systemctl stop redis

# -----------------------------------------------------------------------------#

# Create folder and file for the logs of Redis server
mkdir /mnt/WEBSERVER_LOGS/redis
chown redis /mnt/WEBSERVER_LOGS/redis
chmod 755 /mnt/WEBSERVER_LOGS/redis
touch /mnt/WEBSERVER_LOGS/redis/error.log
chown redis /mnt/WEBSERVER_LOGS/redis/error.log
chmod 644 /mnt/WEBSERVER_LOGS/redis/error.log
rm -rf /var/log/redis

# -----------------------------------------------------------------------------#

# Assign redis user to www-data group
usermod -a -G redis www-data

# -----------------------------------------------------------------------------#

# Customize Redis configuration
rm /etc/redis/redis.conf
wget $REPO/REDIS/redis.conf -O /etc/redis/redis.conf
sed -i "s|\[PASSWORD\]|$REDIS_PASSWORD|" /etc/redis/redis.conf
chattr +i /etc/redis/redis.conf

# -----------------------------------------------------------------------------#

# Change Redis service file to allow using anothe directory for logs
rm /etc/systemd/system/redis.service
wget $REPO/REDIS/redis.service -O /etc/systemd/system/redis.service
chmod 644 /etc/systemd/system/redis.service
chattr +i /etc/redis/redis.service
systemctl daemon-reload

# -----------------------------------------------------------------------------#

systemctl enable redis
systemctl restart redis





#=============================================================================#
#                                                                             #
#                             NEXTCLOUD  SETUP                                #
#                                                                             #
#=============================================================================#

# Download the Nextcloud archive for theversion selected. If the download speed is too low it restart the download
while true; do
    # Start wget with logging
    wget --continue --progress=dot --output-file=wget.log "https://download.nextcloud.com/server/releases/$NEXTCLOUD_VERSION.tar.bz2" -O "/var/www/$NEXTCLOUD_VERSION.tar.bz2" &
    WGET_PID=$!

    # Count how many time the speed got below the threshold
    i=0

    # Iterate the WGET
    while kill -0 $WGET_PID 2> /dev/null; do
        # Monitor the wget log
        lines=$(tail -n 4 wget.log)

        PERCENTAGE="0"
        SPD_NUM="0"
        SPD_MUL="0"

        # Read the lines to extrapolate the values
        while read -r line; do
            PERCENTAGE=$(echo "$line" | awk '{print $7}')
            SPEED=$(echo "$line" | awk '{print $8}')
            SPD_NUM=$(echo $SPEED | grep -Po '([0-9]+\.*[0-9]*)?')
            SPD_MUL=$(echo $SPEED | grep -Po '([KMG])?')
        done < <(echo $lines)

        # Gives a feedback on how the download is going
        echo "$NEXTCLOUD_VERSION.tar.bz2 - Downloaded: $PERCENTAGE"

        # Transform the measured speed in Byte/s
        SPEED_BPS="0"
        if [[ $SPD_MUL == "K" ]]; then
            SPEED_BPS=$(echo "$SPD_NUM * 1024" | bc)
        elif [[ $SPD_MUL == "M" ]]; then
            SPEED_BPS=$(echo "$SPD_NUM * 1024 * 1024" | bc)
        elif [[ $SPD_MUL == "G" ]]; then
            SPEED_BPS=$(echo "$SPD_NUM * 1024 * 1024 * 1024" | bc)
        fi

        # Remove the decimals
        SPEED_BPS=$(echo "$SPEED_BPS" | cut -d '.' -f 1)

        # Compare if the speed is below the threshold
        if (( $SPEED_BPS < $NEXTCLOUD_MIN_SPEED )); then
            ((i++))
        fi

        # If it has gone below the threshold 3 times kill the WGET and restart the loop
        if (( $i > 2 )); then
            kill $WGET_PID
            break
        fi

        sleep 0.5
    done

    # If wget finished successfully, break the loop
    if ! kill -0 $WGET_PID 2> /dev/null; then
        echo "Download complete!"
        break
    fi
done

# -----------------------------------------------------------------------------#

# Unzip the downloaded Nextcloud verion, and remove the archive
tar xvf /var/www/$NEXTCLOUD_VERSION.tar.bz2 -C /var/www/
rm /var/www/$NEXTCLOUD_VERSION.tar.bz2
chown -R www-data:www-data /var/www/nextcloud

# -----------------------------------------------------------------------------#

# Unused sample file
rm /var/www/nextcloud/config/config.sample.php

# -----------------------------------------------------------------------------#

# Restart Apache to clear any error
systemctl restart apache2

# -----------------------------------------------------------------------------#

# Waiting for user to do Nextcloud WebUI installation
echo ""
echo "#===================================================#"
echo "#                                                   #"
echo "#             Web configuration needed!             #"
echo "#                                                   #"
echo "#===================================================#"
echo " When done, type 'continue' to proceed: "
while true; do
    read input
    if [[ "$input" == "continue" ]]; then
        break
    else
        echo "Invalid input. Type 'continue' to proceed:"
    fi
done

# -----------------------------------------------------------------------------#

# Extract needed values, from Nextcloud generated config
nc_instance_id=$(grep "'instanceid'" "/var/www/nextcloud/config/config.php" | awk -F " => '" '{print $2}' | tr -d "',")
nc_password_salt=$(grep "'passwordsalt'" "/var/www/nextcloud/config/config.php" | awk -F " => '" '{print $2}' | tr -d "',")
nc_secret=$(grep "'secret'" "/var/www/nextcloud/config/config.php" | awk -F " => '" '{print $2}' | tr -d "',")
nc_version=$(grep "'version'" "/var/www/nextcloud/config/config.php" | awk -F " => '" '{print $2}' | tr -d "',")

# -----------------------------------------------------------------------------#

# -- Customization config.php --
wget $REPO/NEXTCLOUD/config.php -O /var/www/nextcloud/config/config.php

sed -i "s|\[INSTANCE_ID\]|$nc_instance_id|" /var/www/nextcloud/config/config.php
sed -i "s|\[PASSWORD_SALT\]|$nc_password_salt|" /var/www/nextcloud/config/config.php
sed -i "s|\[SECRET\]|$nc_secret|" /var/www/nextcloud/config/config.php
sed -i "s|\[SERVER_IP\]|$SERVER_IP|" /var/www/nextcloud/config/config.php
sed -i "s|\[EXTERNAL_URL\]|$NEXTCLOUD_URL|" /var/www/nextcloud/config/config.php
sed -i "s|\[VERSION\]|$nc_version|" /var/www/nextcloud/config/config.php
sed -i "s|\[MYSQL_USER\]|$NEXTCLOUD_USER|" /var/www/nextcloud/config/config.php
sed -i "s|\[MYSQL_PASSWORD\]|$NEXTCLOUD_PASSWORD|" /var/www/nextcloud/config/config.php
sed -i "s|\[TIMEZONE\]|$TIMEZONE|" /var/www/nextcloud/config/config.php
sed -i "s|\[REDIS_PASSWORD\]|$REDIS_PASSWORD|" /var/www/nextcloud/config/config.php

sudo -u www-data chmod 600 /var/www/nextcloud/config/config.php

# -----------------------------------------------------------------------------#

# Nextcloud required cronjob for self keeping
crontab -u www-data -l | { cat; echo "*/5 * * * * php /var/www/nextcloud/cron.php"; } | crontab -u www-data -

# -----------------------------------------------------------------------------#

# -- Execute recommended post-installation commands --
sudo -u www-data php /var/www/nextcloud/occ maintenance:repair --include-expensive
sudo -u www-data php /var/www/nextcloud/occ db:add-missing-indices

# -----------------------------------------------------------------------------#

# Modify chunk size from default (10MB) to 2GB
sudo -u www-data php /var/www/nextcloud/occ config:app:set files max_chunk_size --value 2147483648

# Disable user themeing
sudo -u www-data php /var/www/nextcloud/occ theming:config "disable-user-theming" "yes"

# -- Set theme colors --
sudo -u www-data php /var/www/nextcloud/occ theming:config "color" "#00679e"
sudo -u www-data php /var/www/nextcloud/occ theming:config "primary_color" "#00679e"
sudo -u www-data php /var/www/nextcloud/occ theming:config "background" "backgroundColor"
sudo -u www-data php /var/www/nextcloud/occ config:app:set --value "#00679e" theming "background_color"

# Update theme globally
sudo -u www-data php /var/www/nextcloud/occ maintenance:theme:update

# -----------------------------------------------------------------------------#

systemctl restart php$PHP_VERSION-fpm
systemctl restart apache2
