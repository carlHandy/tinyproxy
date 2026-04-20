# Deployment

This guide covers how to deploy and manage **tinyproxy** in a production environment.

## Systemd Service

When installed via `.deb` or `.rpm` packages, **tinyproxy** is automatically configured as a systemd service.

### Management Commands

The `go-tinyproxy` CLI provides convenient wrappers for systemd:

```bash
go-tinyproxy start      # Start the service via systemctl
go-tinyproxy stop       # Stop the service
go-tinyproxy restart    # Restart the service
go-tinyproxy reload     # Reload config without downtime (SIGHUP)
go-tinyproxy status     # Show service status
go-tinyproxy config     # Open vhosts.conf in $EDITOR (defaults to nano)
go-tinyproxy logs       # Tail live logs via journalctl
go-tinyproxy upgrade    # Upgrade to the latest release
go-tinyproxy ssl regenerate  # Clear cert cache and force renewal on next start
```

> **v1.2.17 and earlier — config file prompt:** On Debian/Ubuntu, `dpkg` may interactively prompt about a modified `vhosts.conf` during upgrade. If `go-tinyproxy upgrade` fails with `end of file on stdin at conffile prompt`, run the install manually and choose to keep your version:
> ```bash
> dpkg --force-confold -i /path/to/go-tinyproxy_*.deb
> ```
> This is fixed in v1.2.18+, which passes `--force-confold` automatically.

> The dashboard is not a standalone subcommand. Enable it by passing `--enable-dashboard` and related flags to `go-tinyproxy serve`. See the [Admin Dashboard](./features/dashboard) page for details.

### Manual Service Management

You can also use standard `systemctl` commands:
```bash
sudo systemctl status go-tinyproxy
sudo systemctl restart go-tinyproxy
```

## Reloading Configuration

**tinyproxy** supports zero-downtime configuration reloads. When you modify `vhosts.conf`, you can apply changes by sending a `SIGHUP` signal:

```bash
sudo go-tinyproxy reload
```

This will re-parse the configuration and apply it to the running process without dropping active connections.

## Port Requirements

For automatic TLS (ACME) to work:
- **Port 80**: Must be open to the public for HTTP-01 challenges.
- **Port 443**: Must be open for HTTPS traffic.

If you are running in a restricted environment, ensure these ports are reachable by Let's Encrypt servers.
