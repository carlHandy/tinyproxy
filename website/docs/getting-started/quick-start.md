# Quick Start

Get **tinyproxy** up and running in minutes.

## 1. Local Development Setup

For local development, you need `mkcert` to generate certificates for `localhost`.

```bash
# Install mkcert if you haven't (e.g., brew install mkcert)
mkcert -install

# Generate certificates
mkcert localhost 127.0.0.1 ::1
mkdir -p certs
mv localhost+2.pem certs/
mv localhost+2-key.pem certs/
```

## 2. Basic Configuration

Create a directory named `config` and a file named `vhosts.conf` inside it:

```text
vhosts {
    localhost {
        port 8080
        root ./static
    }
}
```

## 3. Run the Server

Start the server in development mode:

```bash
ENV=dev ./tinyproxy
```

Visit `https://localhost:8080` in your browser. (Note: standard HTTP will automatically redirect to HTTPS).

## 4. Production Deployment

In production, **tinyproxy** automatically manages TLS certificates via Let's Encrypt (ACME).

1. Ensure the server is reachable on ports 80 and 443.
2. Configure your real domain in `config/vhosts.conf`.
3. Run the binary (usually as root or with `CAP_NET_BIND_SERVICE`):
   ```bash
   sudo ./tinyproxy
   ```

Certificates will be automatically obtained and cached in the `certs/` directory.
