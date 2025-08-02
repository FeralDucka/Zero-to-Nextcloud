#!/bin/bash
login_ip="$(echo $SSH_CONNECTION | cut -d " " -f 1)"
login_date="$(date +"%a %e %b %Y, %R")"
login_name="$(whoami)"
message="*Host:* $HOSTNAME"$'\n'"*User:* $login_name"$'\n'"*IP:* $login_ip"$'\n'"$login_date"$'\n\n'"*Login Successfull*"
( /usr/local/sbin/telegram-send "$message" ) &
