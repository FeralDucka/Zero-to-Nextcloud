# &#10024; Zero-to-Nextcloud &#10024;
My personal setup script for making a fresh-installed, bare-metal, Ubuntu/Debian machine in to a hardened full-fledge NextCloud server.<br>
<br>
The setup include:
<ul>
    <li>Nextcloud</li>
    <li>Apache2 (with ModSecurity and ModEvasive) as WebServer</li>
    <li>PHP-FPM as PHP engine</li>
    <li>CertBot for HTTPS certificate</li>
    <li>MySQL as DBMS</li>
    <li>Redis and APCu for caching</li>
    <li>NUT for monitoring the UPS</li>
    <li>Fail2Ban and UFW firewall for security</li>
    <li>+ various scripts to keep everything in check</li>
</ul>
<br>
<br>
The setup take in consideration that <b>my</b> Nextcloud instance is divided on multiple server (one for compute and one for storage) connected via InfiniBand.<br>
<br>
This setup is personal, but feel free to fork it and use it as you want. <br>
<br>
<b>* \( ﾟヮﾟ)/ *</b>

<br>
<br>
<br>

# Setup &#9989;
Remember to customize the variables, in ```setup.sh```, and the configuration files, in base of your needs. <br>
The script must be run as **root**.<br>
```
wget https://raw.githubusercontent.com/FeralDucka/zero-to-nextcloud/main/setup.sh
```
```
chmod +x setup.sh
```
```
sudo ./setup.sh
```

<br>
<br>
<br>

# If things go wrong &#9888;
If the installation process does not complete successfully, is possbile to restart the process.<br>
First must be run ```reset.sh``` to prepare the files and MariaDB database (if it was installed).<br>
Then is possible to run ```setup.sh``` again.<br>
<br>
Remember to customize the variables, in ```reset.sh``` and ```setup.sh```<br>
The script must be run as **root**.<br>
```
wget https://raw.githubusercontent.com/FeralDucka/zero-to-nextcloud/main/reset.sh
```
```
chmod +x reset.sh
```
```
sudo ./reset.sh
```

<br>
<br>
<br>

# Recommended enabled/disabled default Apps &#128295; &#128296;
```
sudo -u www-data php /var/www/nextcloud/occ app:disable app_api
sudo -u www-data php /var/www/nextcloud/occ app:disable circles
sudo -u www-data php /var/www/nextcloud/occ app:disable dashboard
sudo -u www-data php /var/www/nextcloud/occ app:disable firstrunwizard
sudo -u www-data php /var/www/nextcloud/occ app:disable nextcloud_announcements
sudo -u www-data php /var/www/nextcloud/occ app:disable photos
sudo -u www-data php /var/www/nextcloud/occ app:disable sharebymail
sudo -u www-data php /var/www/nextcloud/occ app:disable support
sudo -u www-data php /var/www/nextcloud/occ app:disable weather_status
sudo -u www-data php /var/www/nextcloud/occ app:disable webhook_listeners
```
```
sudo -u www-data php /var/www/nextcloud/occ app:enable suspicious_login
sudo -u www-data php /var/www/nextcloud/occ app:enable twofactor_nextcloud_notification
sudo -u www-data php /var/www/nextcloud/occ app:enable twofactor_totp
```

<br>
<br>
<br>

# Recommended Apps to install &#128301; &#127776;
```
sudo -u www-data php /var/www/nextcloud/occ app:install camerarawpreviews --force
sudo -u www-data php /var/www/nextcloud/occ app:install checksum --force
sudo -u www-data php /var/www/nextcloud/occ app:install epubviewer --force
sudo -u www-data php /var/www/nextcloud/occ app:install files_3dmodelviewer --force
sudo -u www-data php /var/www/nextcloud/occ app:install files_archive --force
sudo -u www-data php /var/www/nextcloud/occ app:install files_automatedtagging --force
sudo -u www-data php /var/www/nextcloud/occ app:install files_downloadactivity --force
sudo -u www-data php /var/www/nextcloud/occ app:install files_markdown --force
sudo -u www-data php /var/www/nextcloud/occ app:install htmlviewer --force
sudo -u www-data php /var/www/nextcloud/occ app:install integration_giphy --force
sudo -u www-data php /var/www/nextcloud/occ app:install integration_openstreetmap --force
sudo -u www-data php /var/www/nextcloud/occ app:install memories --force
sudo -u www-data php /var/www/nextcloud/occ app:install metadata --force
sudo -u www-data php /var/www/nextcloud/occ app:install music --force
sudo -u www-data php /var/www/nextcloud/occ app:install ownershiptransfer --force
sudo -u www-data php /var/www/nextcloud/occ app:install previewgenerator --force
sudo -u www-data php /var/www/nextcloud/occ app:install quota_warning --force
sudo -u www-data php /var/www/nextcloud/occ app:install richdocuments --force
sudo -u www-data php /var/www/nextcloud/occ app:install richdocumentscode --force
sudo -u www-data php /var/www/nextcloud/occ app:install twofactor_webauthn --force
sudo -u www-data php /var/www/nextcloud/occ app:install user_usage_report --force
```
