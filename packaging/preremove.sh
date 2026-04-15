#!/bin/sh
set -e
systemctl stop go-tinyproxy || true
systemctl disable go-tinyproxy || true
