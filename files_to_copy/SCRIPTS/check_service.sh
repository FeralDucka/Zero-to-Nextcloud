#!/bin/bash
LOG_PATH="/mnt/WEBSERVER_LOGS/systemctl_errors/"
if ! systemctl list-units --type=service --all | grep -q "$1.service"; then
  exit 1
fi
if [[ ! -f "$LOG_PATH$1.log" ]]; then
    touch $LOG_PATH$1.log
fi
if ! systemctl is-active --quiet $1; then
  echo "$(date) - $1 - status: stopped" >> $LOG_PATH$1.log
  systemctl restart $1
  if systemctl is-active --quiet $1; then
    echo "$(date) - $1 - status: started" >> $LOG_PATH$1.log
  else
    echo "$(date) - $1 - status: failed to start!" >> $LOG_PATH$1.log
  fi
fi
