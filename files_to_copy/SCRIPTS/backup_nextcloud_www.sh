#!/bin/bash

# Set the output filename with the current date and time
DATE=$(date +"%Y-%m-%d__%H-%M-%S")
FILE_NAME="nextcloud__www__${DATE}"

# Make an archive of the web folder of Nextcloud
tar -czvf "/mnt/NEXTCLOUD_BACKUP/$FILE_NAME.tar.gz" "/var/www/nextcloud"
chmod 400 "/mnt/NEXTCLOUD_BACKUP/$FILE_NAME.tar.gz"
chattr +i "/mnt/NEXTCLOUD_BACKUP/$FILE_NAME.tar.gz"
