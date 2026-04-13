#!/bin/sh
set -e
systemctl daemon-reload
systemctl enable tinyproxy
systemctl start tinyproxy
