#!/bin/bash
duckdns_domain="[DOMAIN]"
duckdns_token="[TOKEN]"
duckdns_url="https://www.duckdns.org/update?domains=$duckdns_domain&token=$duckdns_token&ip="
last_ip_file="/usr/local/sbin/last_ip.txt"
if [[ ! -f "$last_ip_file" ]]; then
    touch $last_ip_file
fi
last_registered_ip=$(cat "$last_ip_file")
current_duckdns_ip=$(curl -s "https://dns.google/resolve?name=$duckdns_domain.duckdns.org&type=A" | sed -n 's/.*"data":"\([0-9.]*\)".*/\1/p')
current_ip=$(curl -s https://api.ipify.org)
if [[ "$last_registered_ip" == "$current_ip" ]] && [[ "$current_duckdns_ip" == "$current_ip" ]]; then
    echo "IP not changed"
elif [[ "$current_duckdns_ip" != "$current_ip" ]]; then
    echo "Wrong DuckDNS IP"
    curl "$duckdns_url$current_ip"
else
    echo "IP changed"
    echo "$current_ip" > "$last_registered_ip"
    curl "$duckdns_url$current_ip"
fi
