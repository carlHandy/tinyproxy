# Docker

**tinyproxy** ships a minimal Docker image based on Alpine Linux. It exposes ports 80 and 443 and runs `go-tinyproxy serve` as its entrypoint.

## Quick Start

```bash
docker run -d \
  -p 80:80 \
  -p 443:443 \
  -v /path/to/your/vhosts.conf:/etc/go-tinyproxy/vhosts.conf:ro \
  kalpadev/tinyproxy:latest
```

The container reads its config from `/etc/go-tinyproxy/vhosts.conf`. Mount your own file to override the bundled default (which serves the built-in static page on port 80).

## Passing CLI Flags

Pass `serve` flags directly after the image name:

```bash
docker run -d \
  -p 80:80 \
  -p 443:443 \
  -v /path/to/vhosts.conf:/etc/go-tinyproxy/vhosts.conf:ro \
  -v /path/to/certs:/var/cache/go-tinyproxy/certs \
  kalpadev/tinyproxy:latest serve \
  --enable-dashboard \
  --dashboard-host 0.0.0.0 \
  --dashboard-port 9000 \
  --dashboard-creds /etc/go-tinyproxy/dashboard.creds \
  --dashboard-db /data/dashboard.db
```

## Docker Compose

```yaml
services:
  tinyproxy:
    image: kalpadev/tinyproxy:latest
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./config/vhosts.conf:/etc/go-tinyproxy/vhosts.conf:ro
      - ./config/fingerprints.conf:/etc/go-tinyproxy/fingerprints.conf:ro
      - certs:/var/cache/go-tinyproxy/certs

volumes:
  certs:
```

## Building from Source

```bash
docker build -t tinyproxy:local .
```

The multi-stage `Dockerfile` compiles the binary with `CGO_ENABLED=0` and copies it into a minimal Alpine image alongside the default config and static files.

## Volumes

| Path in container | Purpose |
|---|---|
| `/etc/go-tinyproxy/vhosts.conf` | Main virtual host configuration |
| `/etc/go-tinyproxy/fingerprints.conf` | JA3/JA4 TLS fingerprint blocklist |
| `/var/cache/go-tinyproxy/certs` | ACME/Let's Encrypt certificate cache |
| `/usr/share/go-tinyproxy/static` | Default static files served by the built-in vhost |

## TLS in Production

Mount a named volume at `/var/cache/go-tinyproxy/certs` to persist ACME certificates across container restarts. Ensure ports 80 and 443 are reachable from the internet for HTTP-01 challenges to succeed.
