#!/bin/sh
set -e
mkdir -p /var/cache/go-tinyproxy/certs
systemctl daemon-reload
systemctl enable go-tinyproxy
systemctl start go-tinyproxy
