#!/bin/bash
duckdns_domain="[DOMAIN]"
duckdns_token="[TOKEN]"
duckdns_url="https://www.duckdns.org/update?domains=$duckdns_domain&token=$duckdns_token&ip="
last_ip_file="/usr/local/sbin/last_ip.txt"
if [[ ! -f "$last_ip_file" ]]; then
    touch $last_ip_file
fi
last_ip=$(cat "$last_ip_file")
current_ip=$(curl -s https://api.ipify.org)
if [[ "$last_ip" == "$current_ip"  ]]; then
    echo "IP not changed"
else
    echo "IP changed"
    echo "$current_ip" > "$last_ip_file"
    curl "$duckdns_url$current_ip"
fi
