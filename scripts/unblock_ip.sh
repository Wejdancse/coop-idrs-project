#!/bin/bash
if [ -z "$1" ]; then
    echo "Usage: $0 <ip_address>"
    exit 1
fi

sudo ufw delete deny from "$1"
echo "Unblocked $1"
sudo ufw status
