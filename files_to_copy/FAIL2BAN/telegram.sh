#!/bin/bash
date="$(date +"%a %e %b %Y, %R")"
if [ $1 = "b" ]; then
    message="*Host:* $HOSTNAME"$'\n'"*Service:* $2"$'\n'"*IP:* $3"$'\n'"$date"$'\n\n'"*!!! IP has been banned !!!*"
elif [ $1 = "u" ]; then
    message="*Host:* $HOSTNAME"$'\n'"*Service:* $2"$'\n'"*IP:* $3"$'\n'"$date"$'\n\n'"*IP has been unbanned.*"
else
    echo "Invalid action: $1"
    exit 1
fi
/usr/local/sbin/telegram-send "$message"
