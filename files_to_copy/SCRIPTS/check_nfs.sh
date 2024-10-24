#!/bin/bash
ping $1 -c 1 > /dev/null 2>&1
if [ $? -eq 0 ]; then
    if ! mountpoint -q "/mnt/$2"; then
        mount $1:/mnt/STORAGE/$2 /mnt/$2
    fi
fi
