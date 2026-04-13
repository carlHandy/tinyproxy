#!/bin/sh
set -e
systemctl stop tinyproxy || true
systemctl disable tinyproxy || true
