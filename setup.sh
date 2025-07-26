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

HOSTNAME="toaster.local"

# -----------------------------------------------------------------------------#

INFINIBAND_INTERFACE="ib1"
LAN_INTERFACE="eth1"

# -----------------------------------------------------------------------------#

LAN_IP="169.254.0.1"
LAN_SUBNET="16"
LAN_GATEWAY="169.254.0.2"
DNS_SERVER_1="1.1.1.1"
DNS_SERVER_2="9.9.9.9"

SSH_IP="169.254.0.3"
SSH_SUBNET="16"

TARGET_NFS_IP="169.254.0.4"
SERVER_NFS_IP="169.254.0.5"
NFS_SUBNET="16"

# -----------------------------------------------------------------------------#

TELEGRAM_KEY="xxxxxx"
TELEGRAM_CHAT_ID="xxxxxx"

# -----------------------------------------------------------------------------#

DUCKDNS_DOMAIN="xxxxxx"
DUCKDNS_TOKEN="xxxxxx"

# -----------------------------------------------------------------------------#

SSH_PUBLIC_KEY="xxxxxx"

# -----------------------------------------------------------------------------#

NTP_SERVER_1="0.it.pool.ntp.org"
NTP_SERVER_2="1.it.pool.ntp.org"
NTP_SERVER_3="2.it.pool.ntp.org"
TIMEZONE="Europe/Rome"

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
NEXTCLOUD_MIN_SPEED=$((5 * 1024 * 1024))
NEXTCLOUD_VERSION="latest"

NEXTCLOUD_URL="example.org"





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

# Installing tool needed to compile telegram-send-py
apt install -y binutils python3-venv

# Installing CRON
apt install -y cron

# Installing SSH server
apt install -y openssh-server

# Installing Chrony to create an NTP server
apt install -y chrony

# Installing Firewall software
apt install -y rsyslog ufw

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

# Installing NUT software
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

# Removing default user from sudo group
deluser $HOST_USER sudo

# -----------------------------------------------------------------------------#

# Create user and group "www-data", used later in the script
groupadd www-data
useradd -M -g www-data -s /usr/sbin/nologin www-data

# -----------------------------------------------------------------------------#

# Disable Power buttons and Lid detections
sed -i 's|^#\s*\(HandlePowerKey=poweroff\)|HandlePowerKey=ignore|' /etc/systemd/logind.conf
sed -i 's|^#\s*\(HandlePowerKeyLongPress=ignore\)|\1|' /etc/systemd/logind.conf
sed -i 's|^#\s*\(HandleRebootKey=reboot\)|HandleRebootKey=ignore|' /etc/systemd/logind.conf
sed -i 's|^#\s*\(HandleRebootKeyLongPress=poweroff\)|HandleRebootKeyLongPress=ignore|' /etc/systemd/logind.conf
sed -i 's|^#\s*\(HandleSuspendKey=suspend\)|HandleSuspendKey=ignore|' /etc/systemd/logind.conf
sed -i 's|^#\s*\(HandleSuspendKeyLongPress=hibernate\)|HandleSuspendKeyLongPress=ignore|' /etc/systemd/logind.conf
sed -i 's|^#\s*\(HandleHibernateKey=hibernate\)|HandleHibernateKey=ignore|' /etc/systemd/logind.conf
sed -i 's|^#\s*\(HandleHibernateKeyLongPress=ignore\)|\1|' /etc/systemd/logind.conf
sed -i 's|^#\s*\(HandleLidSwitch=suspend\)|HandleLidSwitch=ignore|' /etc/systemd/logind.conf
sed -i 's|^#\s*\(HandleLidSwitchExternalPower=suspend\)|HandleLidSwitchExternalPower=ignore|' /etc/systemd/logind.conf
sed -i 's|^#\s*\(HandleLidSwitchDocked=ignore\)|\1|' /etc/systemd/logind.conf

# Lock /etc/systemd/logind.conf file
chmod 444 /etc/systemd/logind.conf
chattr +i /etc/systemd/logind.conf

# Restart the service to apply the configurations
systemctl restart systemd-logind

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
chattr +i /root/.profile

# -----------------------------------------------------------------------------#

# Set nano setting
rm /etc/nanorc
wget $REPO/NANO/nanorc -O /etc/nanorc
chmod 444 /etc/nanorc
chattr +i /etc/nanorc

# -----------------------------------------------------------------------------#

# -- Enable some network security feature of /etc/syctl.conf --
sed -i 's|^#\s*\(net\.ipv4\.conf\.default\.rp_filter=1\)|net\.ipv4\.conf\.default\.rp_filter = 1|' /etc/sysctl.conf
sed -i 's|^#\s*\(net\.ipv4\.conf\.all\.rp_filter=1\)|net\.ipv4\.conf\.all\.rp_filter = 1|' /etc/sysctl.conf

sed -i 's|^#\s*\(net\.ipv4\.tcp_syncookies=1\)|net\.ipv4\.tcp_syncookies = 0|' /etc/sysctl.conf

# Not recommended for security, but needed for redirecting Telegram notifications, from the Storage Server to the internet
sed -i 's|^#\s*\(net\.ipv4\.ip_forward=1\)|net\.ipv4\.ip_forward = 1|' /etc/sysctl.conf

sed -i 's|^#\s*\(net\.ipv6\.conf\.all\.forwarding=1\)|net\.ipv6\.conf\.all\.forwarding = 0|' /etc/sysctl.conf

sed -i 's|^#\s*\(net\.ipv4\.conf\.all\.accept_redirects = 0\)|\1|' /etc/sysctl.conf
sed -i 's|^#\s*\(net\.ipv4\.conf\.default\.accept_redirects = 0\)|\1|' /etc/sysctl.conf

sed -i 's|^#\s*\(net\.ipv4\.conf\.all\.send_redirects = 0\)|\1|' /etc/sysctl.conf
sed -i 's|^#\s*\(net\.ipv4\.conf\.all\.log_martians = 1\)|\1|' /etc/sysctl.conf

# Append this line to /etc/sysctl.conf to stop transmitting the timestamp of the server
grep -qxF 'net.ipv4.tcp_timestamps = 0' /etc/sysctl.conf || echo 'net.ipv4.tcp_timestamps = 0' >> /etc/sysctl.conf

# Lock /etc/sysctl.conf
chmod 400 /etc/sysctl.conf
chattr +i /etc/sysctl.conf

# Load the new parameters
sysctl -p

# -----------------------------------------------------------------------------#

# Create the directory for the keymaps
mkdir /usr/share/keymaps

# Get the new KeyMap from the repo and locks it
wget $REPO/HOMEKEEPING/keymap.map -O /usr/share/keymaps/keymap.map
chmod 400 /usr/share/keymaps/keymap.map
chattr +i /usr/share/keymaps/keymap.map

# Load the new KeyMap
loadkeys /usr/share/keymaps/keymap.map

# Will load the KeyMap at every reboot
crontab -u root -l | { cat; echo "@reboot   loadkeys /usr/share/keymaps/keymap.map"; } | crontab -u root -





#=============================================================================#
#                                                                             #
#                             INFINIBAND  SETUP                               #
#                                                                             #
#=============================================================================#

# Download the file with the required InfiniBand modules
wget $REPO/INFINIBAND/infiniband.conf -O /etc/modules-load.d/infiniband.conf

# -----------------------------------------------------------------------------#

#Add cron job to set the InfiniBand interface in DATAGRAM mode (MTU: 65520)
crontab -u root -l | { cat; echo "@reboot   echo connected > /sys/class/net/$INFINIBAND_INTERFACE/mode"; } | crontab -u root -

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





#=============================================================================#
#                                                                             #
#                              NETWORK  SETUP                                 #
#                                                                             #
#=============================================================================#

# Remove auto-generated network settings
rm /etc/netplan/50-cloud-init.yaml

# Download new networking settings
wget $REPO/NETWORK/50-cloud-init.yaml -O /etc/netplan/50-cloud-init.yaml

# Apply network settings
sed -i "s|\[LAN_IP\]|$LAN_IP/$LAN_SUBNET|" /etc/netplan/50-cloud-init.yaml
sed -i "s|\[DNS_1\]|$DNS_SERVER_1|" /etc/netplan/50-cloud-init.yaml
sed -i "s|\[DNS_2\]|$DNS_SERVER_2|" /etc/netplan/50-cloud-init.yaml
sed -i "s|\[LAN_GATEWAY\]|$LAN_GATEWAY|" /etc/netplan/50-cloud-init.yaml
sed -i "s|\[SSH_IP\]|$SSH_IP/$SSH_SUBNET|" /etc/netplan/50-cloud-init.yaml
sed -i "s|\[NFS_IP\]|$SERVER_NFS_IP/$NFS_SUBNET|" /etc/netplan/50-cloud-init.yaml

# Only root can see the netplan
chmod 400 /etc/netplan/50-cloud-init.yaml
chattr +i /etc/netplan/50-cloud-init.yaml

# -----------------------------------------------------------------------------#

# Apply the new network settings
netplan apply

# -----------------------------------------------------------------------------#

# Set link up the needed interfaces
ip link set $LAN_INTERFACE up
ip link set $INFINIBAND_INTERFACE up

# -----------------------------------------------------------------------------#

# Refresh OpenSM to apply network settings on InfiniBand interfaces
opensm &
OPENSM_PID=$!
sleep 10
kill -SIGTERM $OPENSM_PID

# -----------------------------------------------------------------------------#

# Set InfiniBand interface in DATAGRAM mode (MTU: 65520)
echo connected > /sys/class/net/$INFINIBAND_INTERFACE/mode





#=============================================================================#
#                                                                             #
#                              UTILITY  SCRIPTS                               #
#                                                                             #
#=============================================================================#

# Download custom scripts
wget $REPO/SCRIPTS/backup_nextcloud_db.sh -O /usr/local/sbin/backup_nextcloud_db.sh
wget $REPO/SCRIPTS/backup_nextcloud_www.sh -O /usr/local/sbin/backup_nextcloud_www.sh
wget $REPO/SCRIPTS/check_ib.sh -O /usr/local/sbin/check_ib.sh
wget $REPO/SCRIPTS/check_ip.sh -O /usr/local/sbin/check_ip.sh
wget $REPO/SCRIPTS/check_nfs.sh -O /usr/local/sbin/check_nfs.sh
wget $REPO/SCRIPTS/check_service.sh -O /usr/local/sbin/check_service.sh
wget $REPO/SCRIPTS/ups_notify.sh -O /usr/local/sbin/ups_notify.sh
wget $REPO/SCRIPTS/telegram-send.py -O /usr/local/sbin/telegram-send.py
wget $REPO/SCRIPTS/login-notify.sh -O /etc/profile.d/login-notify.sh

# -----------------------------------------------------------------------------#

# Set up Telegram script with your credentials
sed -i "s|\[API_KEY\]|$TELEGRAM_KEY|" /usr/local/sbin/telegram-send.py
sed -i "s|\[CHAT_ID\]|$TELEGRAM_CHAT_ID|" /usr/local/sbin/telegram-send.py

# Compile Telegram Scrip into binary to mask credentials
python3 -m venv telegram_script_env
source telegram_script_env/bin/activate
python3 -m pip install --upgrade pip
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

#  chmod only root can read and execute the files
chmod 500 /usr/local/sbin/backup_nextcloud_db.sh
chmod 500 /usr/local/sbin/backup_nextcloud_www.sh
chmod 500 /usr/local/sbin/check_ib.sh
chmod 500 /usr/local/sbin/check_ip.sh
chmod 500 /usr/local/sbin/check_nfs.sh
chmod 500 /usr/local/sbin/check_service.sh

#  chmod everyone can only read and execute the files
chmod 555 /usr/local/sbin/ups_notify.sh
chmod 555 /etc/profile.d/login-notify.sh

# -----------------------------------------------------------------------------#

# Make scripts immutable
chattr +i /usr/local/sbin/backup_nextcloud_db.sh
chattr +i /usr/local/sbin/backup_nextcloud_www.sh
chattr +i /usr/local/sbin/check_ib.sh
chattr +i /usr/local/sbin/check_ip.sh
chattr +i /usr/local/sbin/check_nfs.sh
chattr +i /usr/local/sbin/check_service.sh
chattr +i /usr/local/sbin/ups_notify.sh
chattr +i /etc/profile.d/login-notify.sh

# -----------------------------------------------------------------------------#

# -- Add cronjob for checking scripts while server is running --
crontab -u root -l | { cat; echo "  0 3 * * 1  /usr/local/sbin/backup_nextcloud_db.sh"; } | crontab -u root -
crontab -u root -l | { cat; echo "*/1 * * * *  /usr/local/sbin/check_ib.sh"; } | crontab -u root -
crontab -u root -l | { cat; echo "*/5 * * * *  /usr/local/sbin/check_ip.sh"; } | crontab -u root -
crontab -u root -l | { cat; echo "*/1 * * * *  /usr/local/sbin/check_service.sh apache2"; } | crontab -u root -
crontab -u root -l | { cat; echo "*/1 * * * *  /usr/local/sbin/check_service.sh mysql"; } | crontab -u root -
crontab -u root -l | { cat; echo "*/1 * * * *  /usr/local/sbin/check_service.sh php$PHP_VERSION-fpm"; } | crontab -u root -
crontab -u root -l | { cat; echo "*/1 * * * *  /usr/local/sbin/check_service.sh redis"; } | crontab -u root -

# -----------------------------------------------------------------------------#

# -- Add cronjob for checking scripts at reboot --
crontab -u root -l | { cat; echo "@reboot   /usr/local/sbin/check_ib.sh"; } | crontab -u root -
crontab -u root -l | { cat; echo "@reboot   /usr/local/sbin/check_ip.sh"; } | crontab -u root -
crontab -u root -l | { cat; echo "@reboot   /usr/local/sbin/check_service.sh apache2"; } | crontab -u root -
crontab -u root -l | { cat; echo "@reboot   /usr/local/sbin/check_service.sh mysql"; } | crontab -u root -
crontab -u root -l | { cat; echo "@reboot   /usr/local/sbin/check_service.sh php$PHP_VERSION-fpm"; } | crontab -u root -
crontab -u root -l | { cat; echo "@reboot   /usr/local/sbin/check_service.sh redis"; } | crontab -u root -





#=============================================================================#
#                                                                             #
#                              FOLDERS  SETUP                                 #
#                                                                             #
#=============================================================================#

# create required folders for Nextcloud and monitoring
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
/usr/local/sbin/check_nfs.sh $TARGET_NFS_IP NEXTCLOUD_BACKUP
/usr/local/sbin/check_nfs.sh $TARGET_NFS_IP NEXTCLOUD_DATA
/usr/local/sbin/check_nfs.sh $TARGET_NFS_IP NEXTCLOUD_LOGS
/usr/local/sbin/check_nfs.sh $TARGET_NFS_IP WEBSERVER_LOGS

# -----------------------------------------------------------------------------#

# Make folder for check_service.sh logs
mkdir /mnt/WEBSERVER_LOGS/systemctl_errors

# -----------------------------------------------------------------------------#

# Add cronjobs for checking if the NFS folders are mounted
crontab -u root -l | { cat; echo "*/1 * * * * /usr/local/sbin/check_nfs.sh $TARGET_NFS_IP NEXTCLOUD_BACKUP"; } | crontab -u root -
crontab -u root -l | { cat; echo "*/1 * * * * /usr/local/sbin/check_nfs.sh $TARGET_NFS_IP NEXTCLOUD_DATA"; } | crontab -u root -
crontab -u root -l | { cat; echo "*/1 * * * * /usr/local/sbin/check_nfs.sh $TARGET_NFS_IP NEXTCLOUD_LOGS"; } | crontab -u root -
crontab -u root -l | { cat; echo "*/1 * * * * /usr/local/sbin/check_nfs.sh $TARGET_NFS_IP WEBSERVER_LOGS"; } | crontab -u root -

# -----------------------------------------------------------------------------#

# Add cronjobs for mounting the NFS folders at reboot
crontab -u root -l | { cat; echo "@reboot   /usr/local/sbin/check_nfs.sh $TARGET_NFS_IP NEXTCLOUD_BACKUP"; } | crontab -u root -
crontab -u root -l | { cat; echo "@reboot   /usr/local/sbin/check_nfs.sh $TARGET_NFS_IP NEXTCLOUD_DATA"; } | crontab -u root -
crontab -u root -l | { cat; echo "@reboot   /usr/local/sbin/check_nfs.sh $TARGET_NFS_IP NEXTCLOUD_LOGS"; } | crontab -u root -
crontab -u root -l | { cat; echo "@reboot   /usr/local/sbin/check_nfs.sh $TARGET_NFS_IP WEBSERVER_LOGS"; } | crontab -u root -





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
sed -i "s|\[SSH_IP\]|$SSH_IP|" /etc/ssh/sshd_config
chmod 400 /etc/ssh/sshd_config
chattr +i /etc/ssh/sshd_config

# -----------------------------------------------------------------------------#

# Copy the public key to the authorization file
echo $SSH_PUBLIC_KEY > /home/$HOST_USER/.ssh/authorized_keys
chown root:root /home/$HOST_USER/.ssh/authorized_keys
chmod 444 /home/$HOST_USER/.ssh/authorized_keys
chattr +i /home/$HOST_USER/.ssh/authorized_keys

# -----------------------------------------------------------------------------#

# Kill all the SSH connection active (or sshd.service might fail to restart)
sudo lsof -i :22 | awk 'NR>1 && $2 != 1 {print $2}' | xargs sudo kill

# -----------------------------------------------------------------------------#

# Restart the service to load the new configurations
systemctl enable ssh
systemctl restart ssh





#=============================================================================#
#                                                                             #
#                                  NTP  SETUP                                 #
#                                                                             #
#=============================================================================#

# Setting NTP pools
sed -i "s|#NTP=|NTP=$NTP_SERVER_1 $NTP_SERVER_2 $NTP_SERVER_3|" /etc/systemd/timesyncd.conf

# Locking NTP configuration
chmod 400 /etc/systemd/timesyncd.conf
chattr +i /etc/systemd/timesyncd.conf

# Setting Timezone
timedatectl set-timezone $TIMEZONE

# Enable systemd-timedated NTP synchronization
timedatectl set-ntp true

# Reloading NTP service for loading the new configurations
systemctl restart systemd-timedated

# -----------------------------------------------------------------------------#

# Create folder for Chrony log files
mkdir /mnt/WEBSERVER_LOGS/chrony
chown _chrony:_chrony /mnt/WEBSERVER_LOGS/chrony

# Configure Chrony NTP server
rm /etc/chrony/chrony.conf
wget $REPO/NTP/chrony.conf -O /etc/chrony/chrony.conf
sed -i "s|\[POOL_1\]|$NTP_SERVER_1|" /etc/chrony/chrony.conf
sed -i "s|\[POOL_2\]|$NTP_SERVER_2|" /etc/chrony/chrony.conf
sed -i "s|\[POOL_3\]|$NTP_SERVER_3|" /etc/chrony/chrony.conf
sed -i "s|\[REQUEST_INTERFACE\]|$LAN_IP|" /etc/chrony/chrony.conf
sed -i "s|\[SERVER_INTERFACE\]|$SERVER_NFS_IP|" /etc/chrony/chrony.conf
sed -i "s|\[CLIENT_IP\]|$TARGET_NFS_IP/$NFS_SUBNET|" /etc/chrony/chrony.conf

# Lock Chrony configuration
chmod 400 /etc/chrony/chrony.conf
chattr +i /etc/chrony/chrony.conf





#=============================================================================#
#                                                                             #
#                              FIREWALL  SETUP                                #
#                                                                             #
#=============================================================================#

# Change the rules to allow PING to go through
rm /etc/ufw/before.rules
wget $REPO/UFW/before.rules -O /etc/ufw/before.rules
chmod 400 /etc/ufw/before.rules
chattr +i /etc/ufw/before.rules

# -----------------------------------------------------------------------------#

# Enable logging, mode "high"
ufw logging high

# -----------------------------------------------------------------------------#

# Make folder for Firewall log file
mkdir /mnt/WEBSERVER_LOGS/ufw

# Make the new Firewall log file
touch /mnt/WEBSERVER_LOGS/ufw/ufw.log
chown syslog:adm /mnt/WEBSERVER_LOGS/ufw/ufw.log
chmod 640 /mnt/WEBSERVER_LOGS/ufw/ufw.log

# -----------------------------------------------------------------------------#

# Change log file path
rm /etc/rsyslog.d/20-ufw.conf
wget $REPO/UFW/20-ufw.conf -O /etc/rsyslog.d/20-ufw.conf
chmod 400 /etc/rsyslog.d/20-ufw.conf
chattr +i /etc/rsyslog.d/20-ufw.conf

# -----------------------------------------------------------------------------#

# Modify AppArmor to allow the change in log path
sed -i 's|/var/log/\*\*[[:space:]]*rw|/mnt/WEBSERVER_LOGS/ufw       rw\n  /mnt/WEBSERVER_LOGS/ufw/**    rw|' /etc/apparmor.d/usr.sbin.rsyslogd
apparmor_parser -r /etc/apparmor.d/usr.sbin.rsyslogd

# -----------------------------------------------------------------------------#

# Restart RSysLog to change the log filepath and remove the old one
systemctl restart rsyslog
rm /var/log/ufw.log

# -----------------------------------------------------------------------------#

# Disable IPv6 requests
sudo sed -i 's|IPV6=yes|IPV6=no|' /etc/default/ufw
chmod 400 /etc/default/ufw
chattr -i /etc/default/ufw

# -----------------------------------------------------------------------------#

# Deny every request not allowed in the list below
ufw default deny incoming
ufw default deny outgoing

# -----------------------------------------------------------------------------#

# -- Allowed Connections List --
ufw allow in on eth4 to any port 22 proto tcp         # For SSH connection
ufw allow out on eth1 to any port 53 proto tcp        # For DNS queries
ufw allow out on eth1 to any port 53 proto udp        # For DNS queries
ufw allow in on eth1 to any port 80 proto tcp         # For HTTP Nextcloud
ufw allow out on eth1 to any port 80 proto tcp        # For apt update
ufw allow out on eth1 to any port 123 proto udp       # For NTP client
ufw allow in on ib1 to any port 123 proto udp         # For NTP server (request)
ufw allow out on ib1 to any port 123 proto udp        # For NTP server (answer)
ufw allow in on eth1 to any port 443 proto tcp        # For HTTPS Nextcloud
ufw allow out on eth1 to any port 443 proto tcp       # For Telegram script / wget GitHub
ufw allow in on ib1 to any port 2049                  # For NFS
ufw allow out on ib1 to any port 2049                 # For NFS
ufw allow in on ib1 to any port 3493 proto tcp        # For NUT

# -----------------------------------------------------------------------------#

# Enable UFW Firewall
echo "y" | ufw enable

# -----------------------------------------------------------------------------#

# -- Add a passthrough for Telegram notifications from storage server to the internet (throug the already exposed compute server) --
crontab -u root -l | { cat; echo "@reboot   iptables -A FORWARD -i $INFINIBAND_INTERFACE -o $LAN_INTERFACE -j ACCEPT"; } | crontab -u root -
crontab -u root -l | { cat; echo "@reboot   iptables -A FORWARD -i $LAN_INTERFACE -o $INFINIBAND_INTERFACE -m state --state ESTABLISHED,RELATED -j ACCEPT"; } | crontab -u root -
crontab -u root -l | { cat; echo "@reboot   iptables -t nat -A POSTROUTING -o $LAN_INTERFACE -j MASQUERADE"; } | crontab -u root -





#=============================================================================#
#                                                                             #
#                              FAIL2BAN  SETUP                                #
#                                                                             #
#=============================================================================#

# Folder for Fail2Ban logs
mkdir /mnt/WEBSERVER_LOGS/fail2ban
chown root:adm /mnt/WEBSERVER_LOGS/fail2ban

# -----------------------------------------------------------------------------#

# Folder for Telegram notifications script
mkdir /etc/fail2ban/scripts/

# -----------------------------------------------------------------------------#

# Get files from the repo
wget $REPO/FAIL2BAN/fail2ban.local -O /etc/fail2ban/fail2ban.local
wget $REPO/FAIL2BAN/jail.local -O /etc/fail2ban/jail.local
wget $REPO/FAIL2BAN/telegram.conf -O /etc/fail2ban/action.d/telegram.conf
wget $REPO/FAIL2BAN/telegram.sh -O /etc/fail2ban/scripts/telegram.sh

# -----------------------------------------------------------------------------#

# Set files permissions
chmod 400 /etc/fail2ban/fail2ban.local
chmod 400 /etc/fail2ban/jail.local
chmod 400 /etc/fail2ban/action.d/telegram.conf
chmod 500 /etc/fail2ban/scripts/telegram.sh

# -----------------------------------------------------------------------------#

# Make files immutable
chattr +i /etc/fail2ban/fail2ban.local
chattr +i /etc/fail2ban/jail.local
chattr +i /etc/fail2ban/action.d/telegram.conf
chattr +i /etc/fail2ban/scripts/telegram.sh

# -----------------------------------------------------------------------------#

systemctl enable fail2ban
systemctl start fail2ban

# -----------------------------------------------------------------------------#

# Remove old Log file
rm /var/log/fail2ban.log




#=============================================================================#
#                                                                             #
#                                NUT  SETUP                                   #
#                                                                             #
#=============================================================================#

rm /etc/nut/ups.conf
rm /etc/nut/upsd.conf
rm /etc/nut/nut.conf
rm /etc/nut/upsmon.conf
rm /etc/nut/upsd.users

# -----------------------------------------------------------------------------#

wget $REPO/NUT/ups.conf -O /etc/nut/ups.conf
wget $REPO/NUT/upsd.conf -O /etc/nut/upsd.conf
wget $REPO/NUT/nut.conf -O /etc/nut/nut.conf
wget $REPO/NUT/upsmon.conf -O /etc/nut/upsmon.conf
wget $REPO/NUT/upsd.users -O /etc/nut/upsd.users

# -----------------------------------------------------------------------------#

chown root:nut /etc/nut/ups.conf
chown root:nut /etc/nut/upsd.conf
chown root:nut /etc/nut/nut.conf
chown root:nut /etc/nut/upsmon.conf
chown root:nut /etc/nut/upsd.users

chmod 640 /etc/nut/ups.conf
chmod 640 /etc/nut/upsd.conf
chmod 640 /etc/nut/nut.conf
chmod 640 /etc/nut/upsmon.conf
chmod 640 /etc/nut/upsd.users

chattr +i /etc/nut/ups.conf
chattr +i /etc/nut/upsd.conf
chattr +i /etc/nut/nut.conf
chattr +i /etc/nut/upsmon.conf
chattr +i /etc/nut/upsd.users

# -----------------------------------------------------------------------------#

# For the script ups_notify.sh
touch /usr/local/sbin/last_ups_notication.txt
chown nut:nut /usr/local/sbin/last_ups_notication.txt
chmod 600 /usr/local/sbin/last_ups_notication.txt

# -----------------------------------------------------------------------------#

# Restart the services to apply the new configurations
systemctl restart nut-server
systemctl restart nut-monitor
systemctl restart nut-client





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

# Diable server-status page (Vulnerability)
a2dismod status

# Disable compatibility with configurations made for Apache 2.2 or earlyer
a2dismod access_compat

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
openssl req -x509 -new -nodes -key "$APACHE_CA_KEY" -sha256 -days 3650 -out "$APACHE_CA_CRT" -subj "/C=IT/ST=State/L=City/O=Organization/OU=Department/CN=localhost"

# -- Make www-data own the files
chown www-data:www-data $APACHE_CA_KEY
chown www-data:www-data $APACHE_CA_CRT

# -- Lock the files --
chmod 400 $APACHE_CA_KEY
chmod 400 $APACHE_CA_CRT

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

# Remove ModSecurity.conf template
rm /etc/modsecurity/modsecurity.conf-recommended

# -----------------------------------------------------------------------------#

# ModSecurity.conf configuration
rm /etc/modsecurity/modsecurity.conf
wget $REPO/MODSECURITY/modsecurity.conf -O /etc/modsecurity/modsecurity.conf
chmod 400 /etc/modsecurity/modsecurity.conf
chattr +i /etc/modsecurity/modsecurity.conf

# -----------------------------------------------------------------------------#

# ModSecurity Apache2 module configuration
rm /etc/apache2/mods-available/security2.conf
wget $REPO/MODSECURITY/security2.conf -O /etc/apache2/mods-available/security2.conf
chmod 400 /etc/apache2/mods-available/security2.conf
chattr +i /etc/apache2/mods-available/security2.conf

# -----------------------------------------------------------------------------#

mkdir /etc/modsecurity/plugins
mkdir /etc/modsecurity/rules

# -----------------------------------------------------------------------------#

# Download latest version of OWAS Core Rule Set (CRS)
VER=$(curl --silent -qI https://github.com/coreruleset/coreruleset/releases/latest | awk -F '/' '/^location/ {print  substr($NF, 1, length($NF)-1)}')
wget https://github.com/coreruleset/coreruleset/releases/download/$VER/coreruleset-${VER#v}-minimal.tar.gz -P /etc/modsecurity/
tar xvf /etc/modsecurity/coreruleset-${VER#v}-minimal.tar.gz -C /etc/modsecurity/
rm /etc/modsecurity/coreruleset-${VER#v}-minimal.tar.gz

# -----------------------------------------------------------------------------#

# Copying the needed files to the right location
mv -f /etc/modsecurity/coreruleset-${VER#v}/rules/* /etc/modsecurity/rules/
mv -f /etc/modsecurity/coreruleset-${VER#v}/crs-setup.conf.example /etc/modsecurity/crs/

# -----------------------------------------------------------------------------#

# Removing left-over folders
rm -rf /etc/modsecurity/coreruleset-${VER#v}

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
chmod 400 /etc/apache2/mods-available/evasive.conf
chattr +i /etc/apache2/mods-available/evasive.conf

# -----------------------------------------------------------------------------#

systemctl restart apache2





#=============================================================================#
#                                                                             #
#                               CERTBOT  SETUP                                #
#                                                                             #
#=============================================================================#

# Enable editing of the Virtual Host file
chattr -i /etc/apache2/sites-available/nextcloud.conf
chmod 666 /etc/apache2/sites-available/nextcloud.conf

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
chmod 400 /etc/apache2/sites-available/nextcloud.conf
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
chown mysql:mysql /etc/ssl/private/mysql

# -----------------------------------------------------------------------------#

# -- Generate needed SSL files for MySQL server --

# Step 1: Generate CA Key and Certificate
echo "Generating Certificate Authority (CA) Key and Certificate..."
openssl genrsa -out "$MYSQL_CA_KEY" 4096
openssl req -x509 -new -nodes -key "$MYSQL_CA_KEY" -sha256 -days 3650 -out "$MYSQL_CA_CRT" -subj "/C=IT/ST=State/L=City/O=Organization/OU=Department/CN=localhost"

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

chmod 400 $MYSQL_CA_KEY
chmod 400 $MYSQL_CA_CRT
chmod 400 $MYSQL_SERVER_KEY
chmod 400 $MYSQL_SERVER_CRT

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

# -----------------------------------------------------------------------------#

# Remove old Log file
rm /var/log/php${PHP_VERSION}-fpm.log





#=============================================================================#
#                                                                             #
#                                REDIS  SETUP                                 #
#                                                                             #
#=============================================================================#

# Stop redis to avoid error while change the configuration
systemctl stop redis

# -----------------------------------------------------------------------------#

# Create folder for the logs of Redis server
mkdir /mnt/WEBSERVER_LOGS/redis
chown redis:redis /mnt/WEBSERVER_LOGS/redis
chmod 755 /mnt/WEBSERVER_LOGS/redis

# Create file for the logs of Redis server
touch /mnt/WEBSERVER_LOGS/redis/error.log
chown redis:redis /mnt/WEBSERVER_LOGS/redis/error.log
chmod 644 /mnt/WEBSERVER_LOGS/redis/error.log

# -----------------------------------------------------------------------------#

# Assign redis user to www-data group
usermod -a -G redis www-data

# -----------------------------------------------------------------------------#

# Customize Redis configuration
rm /etc/redis/redis.conf
wget $REPO/REDIS/redis.conf -O /etc/redis/redis.conf
sed -i "s|\[PASSWORD\]|$REDIS_PASSWORD|" /etc/redis/redis.conf
chown redis:redis /etc/redis/redis.conf
chmod 444 /etc/redis/redis.conf
chattr +i /etc/redis/redis.conf

# -----------------------------------------------------------------------------#

# Change Redis service file to allow using anothe directory for logs
rm /etc/systemd/system/redis.service
wget $REPO/REDIS/redis.service -O /etc/systemd/system/redis.service
chmod 644 /etc/systemd/system/redis.service
chattr +i /etc/systemd/system/redis.service
systemctl daemon-reload

# -----------------------------------------------------------------------------#

systemctl enable redis
systemctl restart redis

# -----------------------------------------------------------------------------#

# Remove old Log file
rm -rf /var/log/redis





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

        # Check if the parsed line got the right results (speed is  anumber)
        if [[ $SPD_NUM =~ ^-?[0-9]+(\.[0-9]+)?$ ]]; then

            # Transform the measured speed in Byte/s
            SPEED_BPS="0"
            if [[ $SPD_MUL == "K" ]]; then
                SPEED_BPS=$(awk -v spd="$SPD_NUM" 'BEGIN {print int(spd * 1024 + 0.5)}')
            elif [[ $SPD_MUL == "M" ]]; then
                SPEED_BPS=$(awk -v spd="$SPD_NUM" 'BEGIN {print int(spd * 1024 * 1024 + 0.5)}')
            elif [[ $SPD_MUL == "G" ]]; then
                SPEED_BPS=$(awk -v spd="$SPD_NUM" 'BEGIN {print int(spd * 1024 * 1024 * 1024 + 0.5)}')
            fi

            # Compare if the speed is below the threshold
            if (( $SPEED_BPS < $NEXTCLOUD_MIN_SPEED )); then
                ((i++))
            else
                i=0
            fi

            # If it has gone below the threshold 3 times kill the WGET and restart the loop
            if (( $i > 2 )); then
                kill $WGET_PID
                echo "- Download socket restarted"
                break
            fi

            # Gives a feedback on the download progress
            echo "$NEXTCLOUD_VERSION.tar.bz2 - Downloaded: $PERCENTAGE ($SPD_NUM ${SPD_MUL}B/s)"
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

# Create Update Directory for the updater of NextCloud
mkdir /var/www/nextcloud_update
chown -R www-data:www-data /var/www/nextcloud_update

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
sed -i "s|\[LAN_IP\]|$LAN_IP|" /var/www/nextcloud/config/config.php
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

# Update .htaccess
sudo -u www-data php /var/www/nextcloud/occ maintenance:update:htaccess

# -----------------------------------------------------------------------------#

# Modify chunk size from default (10MB) to 2GB
sudo -u www-data php /var/www/nextcloud/occ config:app:set files max_chunk_size --value 2147483648

# -----------------------------------------------------------------------------#

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

# -- Restart services to reload all the new configurations --
systemctl restart php$PHP_VERSION-fpm
systemctl restart apache2

# -----------------------------------------------------------------------------#

# -- Make a backup of NextCloud --
/usr/local/sbin/backup_nextcloud_db.sh
/usr/local/sbin/backup_nextcloud_www.sh
