# Docker Support Design

**Date:** 2026-04-17  
**Status:** Approved  
**Topic:** Full Docker support with multi-platform images pushed to Docker Hub on release

---

## Overview

Add Docker image support to tinyproxy so that every tagged release automatically builds and pushes a multi-platform (`linux/amd64` + `linux/arm64`) image to `kalpadev/tinyproxy` on Docker Hub. The implementation extends the existing GoReleaser setup — no new release tooling is introduced.

---

## Architecture

### Approach

GoReleaser-native Docker. The existing `.goreleaser.yaml` gains two new blocks:

- **`dockers:`** — builds one arch-specific image per platform using the pre-compiled binary from GoReleaser's `dist/` output. GoReleaser injects the binary via `extra_files`; no Go compilation happens inside Docker.
- **`docker_manifests:`** — stitches the two arch images into a single multi-arch manifest.

The existing `release.yml` workflow is extended with Docker login and buildx setup steps.

### Release flow (on tag push)

1. GitHub Actions triggers on `*` tag (existing behaviour)
2. `docker/setup-buildx-action` makes `buildx` available
3. `docker/login-action` authenticates to Docker Hub using repo secrets
4. GoReleaser builds binaries for all platforms (existing behaviour)
5. GoReleaser builds and pushes arch-specific images: `kalpadev/tinyproxy:<version>-amd64` and `kalpadev/tinyproxy:<version>-arm64`
6. GoReleaser creates and pushes multi-arch manifests: `kalpadev/tinyproxy:<version>` and `kalpadev/tinyproxy:latest`

---

## Components

### 1. Dockerfiles

Two Dockerfiles are needed because GoReleaser runs `docker buildx build` in its own temp dir containing the pre-built binary — it cannot skip a builder stage in the standard `Dockerfile`.

**`Dockerfile`** (repo root) — for local `docker build`:
- Stage 1 (builder): `golang:1.25-alpine` — compiles the binary
- Stage 2 (runtime): `alpine:3.21` with `ca-certificates` and `tzdata`

**`Dockerfile.goreleaser`** (repo root) — used by GoReleaser only:
- Single stage: `alpine:3.21` with `ca-certificates` and `tzdata`
- `COPY go-tinyproxy /usr/local/bin/go-tinyproxy` — binary is injected by GoReleaser into its build context

The `dockers:` block in `.goreleaser.yaml` references `Dockerfile.goreleaser` via `dockerfile: Dockerfile.goreleaser`.

Both Dockerfiles produce identical runtime images. Files baked into the image:

| Source | Destination in image |
|--------|----------------------|
| Binary (`go-tinyproxy`) | `/usr/local/bin/go-tinyproxy` |
| `docker/vhosts.default.conf` | `/etc/go-tinyproxy/vhosts.conf` |
| `config/fingerprints.conf` | `/etc/go-tinyproxy/fingerprints.conf` |
| `static/` | `/usr/share/go-tinyproxy/static/` |

Exposed ports: `80`, `443`.  
Entrypoint: `go-tinyproxy`.

Expected user volume mounts:
| Mount path | Purpose |
|------------|---------|
| `/etc/go-tinyproxy/` | Override config |
| `/etc/certs/` | TLS certificates |
| `/var/lib/go-tinyproxy/` | SQLite DB persistence |

### 2. `docker/vhosts.default.conf`

A minimal config baked into the image that makes the container functional out of the box (`docker run -p 80:80 kalpadev/tinyproxy`). Serves static files from `/usr/share/go-tinyproxy/static/` on port 80, no TLS, with basic security headers.

```
vhosts {
    default {
        port 80
        root /usr/share/go-tinyproxy/static

        security {
            frame_options SAMEORIGIN
            content_type nosniff
            xss_protection "1; mode=block"
        }
    }
}
```

This file is separate from `config/vhosts.conf` (the repo's dev/example config), which is unchanged.

### 3. `.goreleaser.yaml` additions

**`dockers:` block** — two entries, one per arch:

```yaml
dockers:
  - image_templates:
      - "kalpadev/tinyproxy:{{ .Version }}-amd64"
    use: buildx
    build_flag_templates:
      - "--platform=linux/amd64"
    goarch: amd64
    goos: linux
    extra_files:
      - docker/vhosts.default.conf
      - config/fingerprints.conf
      - static/

  - image_templates:
      - "kalpadev/tinyproxy:{{ .Version }}-arm64"
    use: buildx
    build_flag_templates:
      - "--platform=linux/arm64"
    goarch: arm64
    goos: linux
    extra_files:
      - docker/vhosts.default.conf
      - config/fingerprints.conf
      - static/
```

**`docker_manifests:` block**:

```yaml
docker_manifests:
  - name_template: "kalpadev/tinyproxy:{{ .Version }}"
    image_templates:
      - "kalpadev/tinyproxy:{{ .Version }}-amd64"
      - "kalpadev/tinyproxy:{{ .Version }}-arm64"

  - name_template: "kalpadev/tinyproxy:latest"
    image_templates:
      - "kalpadev/tinyproxy:{{ .Version }}-amd64"
      - "kalpadev/tinyproxy:{{ .Version }}-arm64"
```

### 4. `.github/workflows/release.yml` additions

Two new steps added before GoReleaser runs:

```yaml
- name: Set up Docker Buildx
  uses: docker/setup-buildx-action@v3

- name: Log in to Docker Hub
  uses: docker/login-action@v3
  with:
    username: ${{ secrets.DOCKERHUB_USERNAME }}
    password: ${{ secrets.DOCKERHUB_TOKEN }}
```

Two new secrets required in the GitHub repo settings:
- `DOCKERHUB_USERNAME` — Docker Hub username (`kalpadev`)
- `DOCKERHUB_TOKEN` — Docker Hub access token (not password — create a token at hub.docker.com)

---

## Data Flow

```
Tag push
  └─> GitHub Actions
        ├─> setup-buildx
        ├─> docker login (DOCKERHUB_USERNAME + DOCKERHUB_TOKEN)
        └─> GoReleaser
              ├─> go build (linux/amd64, linux/arm64, windows/amd64, ...)
              ├─> docker buildx → kalpadev/tinyproxy:<ver>-amd64  (pushed)
              ├─> docker buildx → kalpadev/tinyproxy:<ver>-arm64  (pushed)
              ├─> docker manifest → kalpadev/tinyproxy:<ver>       (pushed)
              ├─> docker manifest → kalpadev/tinyproxy:latest      (pushed)
              ├─> .deb / .rpm packages
              └─> GitHub Release (binaries + packages)
```

---

## Error Handling

- If Docker Hub login fails, GoReleaser aborts before building images — the release still creates binaries and packages via the GitHub Release, but no Docker images are pushed.
- If one arch image push fails, the manifest step will also fail — partial pushes won't leave a broken `latest` tag because GoReleaser only pushes manifests after all image pushes succeed.

---

## Image Signing & SBOM Attestation

Implemented via [Sigstore](https://sigstore.dev) cosign **keyless signing** — no key pairs to manage. The GitHub Actions OIDC token is used as the signing identity, and signatures are recorded in Sigstore's public transparency log (Rekor).

### What gets signed / attested

| Artifact | How |
|----------|-----|
| Docker images (both arch-specific and manifests) | `cosign sign` |
| SBOM documents (CycloneDX JSON, one per binary) | Attached to GitHub Release by GoReleaser |
| Docker image SBOM attestation | `cosign attest` with CycloneDX predicate |

### GoReleaser additions

**`sboms:` block** — generates a CycloneDX SBOM for each binary artifact and attaches it to the GitHub Release:

```yaml
sboms:
  - artifacts: binary
    documents:
      - "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}.sbom.json"
```

**`docker_signs:` block** — signs every pushed image and manifest using cosign keyless:

```yaml
docker_signs:
  - cmd: cosign
    args:
      - sign
      - "--yes"
      - "${artifact}@${digest}"
    artifacts: all
```

### `.github/workflows/release.yml` additions

One new step (before GoReleaser):

```yaml
- name: Install cosign
  uses: sigstore/cosign-installer@v3
```

Updated `permissions` block (add `id-token: write` for OIDC keyless signing):

```yaml
permissions:
  contents: write
  id-token: write
```

### Verification (end-users)

```bash
cosign verify kalpadev/tinyproxy:v1.2.0 \
  --certificate-identity-regexp "https://github.com/carlHandy/go-tinyproxy" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
```

---

## Out of scope

- A `docker-compose.yml` example (useful but a separate concern)
- Automatic `latest` pinning to a non-release branch (only tags trigger releases)
