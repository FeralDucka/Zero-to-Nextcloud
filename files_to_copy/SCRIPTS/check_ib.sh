#!/bin/bash
echo "$ibstat" | while read -r line; do
    if [[ "$line" =~ State:\ Initializing ]]; then
        echo $1 > /sys/bus/pci/drivers/mlx4_core/unbind
        echo $1 > /sys/bus/pci/drivers/mlx4_core/bind
        exit 0
    fi
done
