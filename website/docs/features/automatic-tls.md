# Automatic TLS

**tinyproxy** handles TLS termination and HTTP→HTTPS redirection automatically — no configuration is required to get HTTPS working. Certificates are provisioned and renewed without any external tools.

## How It Works

When running in production mode, tinyproxy:

- Listens on **port 443** for HTTPS traffic.
- Spawns an **HTTP→HTTPS redirect** on port 80 automatically.
- Provisions and renews TLS certificates without any manual steps or restarts.

There is no `ssl` directive needed to enable this. HTTPS is on by default in production.

## Bringing Your Own Certificate

The `ssl` block exists solely to override the automatic certificate with a custom one:

```nginx
example.com {
    proxy_pass http://backend:8080;

    ssl {
        cert /etc/certs/example.com.crt
        key  /etc/certs/example.com.key
    }
}
```

| Directive | Description                              |
| --------- | ---------------------------------------- |
| `cert`    | Path to the PEM-encoded certificate file |
| `key`     | Path to the PEM-encoded private key file |

Omitting the `ssl` block entirely is the normal case — tinyproxy manages the certificate for you.

## Dev vs Production

| Mode        | How to run              | TLS behaviour                                    |
| ----------- | ----------------------- | ------------------------------------------------ |
| Development | `ENV=dev go run ./...`  | Listens on `:8080`, loads certs from `certs/`   |
| Production  | `go run ./...`          | Listens on `:443`, auto HTTP→HTTPS on `:80`      |

In dev mode, generate local certs with [mkcert](https://github.com/FiloSottile/mkcert):

```bash
mkcert localhost 127.0.0.1 ::1
# place output at certs/localhost+2.pem and certs/localhost+2-key.pem
```

See [Security & TLS](./security) for TLS hardening options (cipher suites, HSTS, etc.).
