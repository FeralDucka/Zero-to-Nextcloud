#!/bin/bash

date="$(date +"%a %e %b %Y, %R")"
last_notification_file="/usr/local/sbin/last_ups_notification.txt"
last_notification=$(cat $last_notification_file)

if [ ! "$NOTIFYTYPE" = "$last_notification" ]; then
    if [ "$NOTIFYTYPE" = "ONLINE" ]; then
        message=$(echo "*Host:* $(hostname)"'\n'"$date"'\n\n'"*UPS power restored*")
    fi

    if [ "$NOTIFYTYPE" = "ONBATT" ]; then
        message=$(echo "*Host:* $(hostname)"'\n'"$date"'\n\n'"*UPS on battery!!*")
    fi

    if [ "$NOTIFYTYPE" = "LOWBATT" ]; then
        message=$(echo "*Host:* $(hostname)"'\n'"$date"'\n\n'"*UPS battery low!!*")
    fi

    /usr/local/sbin/telegram-send "$message"

    echo "$NOTIFYTYPE" > $last_notification_file
fi
