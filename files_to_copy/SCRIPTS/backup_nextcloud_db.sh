#!/bin/bash

DB_NAME="nextcloud"

# Set the output filename with the current date and time
DATE=$(date +"%Y-%m-%d__%H-%M-%S")
FILE_NAME="${DB_NAME}__sql__${DATE}"

# Perform the export with mysqldump (you may need to add user credentials)
mysqldump "$DB_NAME" > "/mnt/NEXTCLOUD_BACKUP/$FILE_NAME.sql"

# Compress the file to save space
tar -czf "/mnt/NEXTCLOUD_BACKUP/$FILE_NAME.tar.gz" "/mnt/NEXTCLOUD_BACKUP/$FILE_NAME.sql"
chmod 400 "/mnt/NEXTCLOUD_BACKUP/$FILE_NAME.tar.gz"
chattr +i "/mnt/NEXTCLOUD_BACKUP/$FILE_NAME.tar.gz"

# Remove uncompressed file
rm "/mnt/NEXTCLOUD_BACKUP/$FILE_NAME.sql"
