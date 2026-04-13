#!/bin/sh
set -e
mkdir -p /var/cache/tinyproxy/certs
systemctl daemon-reload
systemctl enable tinyproxy
systemctl start tinyproxy
