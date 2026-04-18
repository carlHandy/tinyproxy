---
sidebar_position: 1
---

# Introduction

**tinyproxy** is a security-focused reverse proxy and web server — a single-binary alternative to nginx + Traefik with native bot detection and AI crawler prevention built into the request pipeline.

It is designed to be lightweight, easy to configure, and highly secure by default.

## Key Features

- **Native Bot Protection**: Opt-in middleware to block known scanners and AI crawlers.
- **Honeypot Mode**: Serve fake content to slow down and misdirect automated scanners.
- **Automatic TLS**: Integrated ACME support for Let's Encrypt certificates.
- **High Performance**: Built with Go for excellent concurrency and low resource usage.
- **Custom Configuration DSL**: A clean, readable configuration format for virtual hosts.
- **Admin Dashboard**: Real-time observability and management via a web-based dashboard.
- **Rich Connectivity**: Supports FastCGI (PHP), SOCKS5 upstreams, and advanced load balancing.

## Why tinyproxy?

Conventional web servers often require complex third-party modules or external scripts for effective bot detection and security hardening. **tinyproxy** brings these "superpowers" into the core binary, allowing you to secure your applications with minimal effort.
