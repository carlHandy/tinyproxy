# Docker Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and push multi-platform Docker images (`linux/amd64` + `linux/arm64`) to `kalpadev/tinyproxy` on Docker Hub as part of every tagged release, with cosign keyless signing and SBOM generation.

**Architecture:** GoReleaser-native Docker — extend `.goreleaser.yaml` with `dockers:`, `docker_manifests:`, `sboms:`, and `docker_signs:` blocks. The existing release workflow gains three pre-GoReleaser steps (buildx setup, Docker Hub login, tool installs). Two Dockerfiles: one multi-stage for local `docker build`, one single-stage for GoReleaser which injects the pre-built binary.

**Tech Stack:** Go 1.25, GoReleaser v2, Docker Buildx, Alpine 3.21, cosign (Sigstore keyless), syft (SBOM), GitHub Actions

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `docker/vhosts.default.conf` | Minimal working config baked into image |
| Create | `Dockerfile` | Multi-stage build for local `docker build` use |
| Create | `Dockerfile.goreleaser` | Single-stage build used by GoReleaser (receives pre-built binary) |
| Modify | `.goreleaser.yaml` | Add `dockers:`, `docker_manifests:`, `sboms:`, `docker_signs:` |
| Modify | `.github/workflows/release.yml` | Add buildx, Docker Hub login, syft, cosign steps; `id-token: write` permission |

---

## Task 1: Create `docker/vhosts.default.conf`

**Files:**
- Create: `docker/vhosts.default.conf`

- [ ] **Step 1: Create the directory and file**

```bash
mkdir -p docker
```

Create `docker/vhosts.default.conf`:

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

- [ ] **Step 2: Commit**

```bash
git add docker/vhosts.default.conf
git commit -m "feat(docker): add default vhosts config for container"
```

---

## Task 2: Create `Dockerfile.goreleaser`

This is the Dockerfile GoReleaser uses. GoReleaser builds the binary externally, then runs `docker buildx build` in a temp directory containing:
- `go-tinyproxy` (the pre-built binary, placed at context root)
- All `extra_files` with their directory structure preserved

**Files:**
- Create: `Dockerfile.goreleaser`

- [ ] **Step 1: Create the file**

Create `Dockerfile.goreleaser` at repo root:

```dockerfile
FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
COPY go-tinyproxy /usr/local/bin/go-tinyproxy
COPY docker/vhosts.default.conf /etc/go-tinyproxy/vhosts.conf
COPY config/fingerprints.conf /etc/go-tinyproxy/fingerprints.conf
COPY static/ /usr/share/go-tinyproxy/static/
EXPOSE 80 443
ENTRYPOINT ["go-tinyproxy"]
```

- [ ] **Step 2: Commit**

```bash
git add Dockerfile.goreleaser
git commit -m "feat(docker): add GoReleaser single-stage Dockerfile"
```

---

## Task 3: Create `Dockerfile` (local multi-stage build)

This Dockerfile is for developers who want to run `docker build .` locally. It compiles the binary itself so it doesn't depend on GoReleaser's dist output. The resulting image is identical to the GoReleaser-built one.

**Files:**
- Create: `Dockerfile`

- [ ] **Step 1: Create the file**

Create `Dockerfile` at repo root:

```dockerfile
FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o go-tinyproxy ./cmd/tinyproxy/

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /src/go-tinyproxy /usr/local/bin/go-tinyproxy
COPY docker/vhosts.default.conf /etc/go-tinyproxy/vhosts.conf
COPY config/fingerprints.conf /etc/go-tinyproxy/fingerprints.conf
COPY static/ /usr/share/go-tinyproxy/static/
EXPOSE 80 443
ENTRYPOINT ["go-tinyproxy"]
```

- [ ] **Step 2: Verify the local build works**

```bash
docker build -t tinyproxy-local .
```

Expected: build completes, final stage is Alpine-based. No errors.

- [ ] **Step 3: Verify the container starts**

```bash
docker run --rm -p 8080:80 tinyproxy-local
```

Expected: server starts and listens. In another terminal:

```bash
curl -i http://localhost:8080/
```

Expected: HTTP 200 or 301 response (serving `static/index.html`). No crash.

- [ ] **Step 4: Commit**

```bash
git add Dockerfile
git commit -m "feat(docker): add multi-stage Dockerfile for local builds"
```

---

## Task 4: Extend `.goreleaser.yaml` — Docker image builds

**Files:**
- Modify: `.goreleaser.yaml`

- [ ] **Step 1: Open `.goreleaser.yaml` and add the `dockers:` block after the `archives:` block**

Append to `.goreleaser.yaml`:

```yaml
dockers:
  - image_templates:
      - "kalpadev/tinyproxy:{{ .Version }}-amd64"
    dockerfile: Dockerfile.goreleaser
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
    dockerfile: Dockerfile.goreleaser
    use: buildx
    build_flag_templates:
      - "--platform=linux/arm64"
    goarch: arm64
    goos: linux
    extra_files:
      - docker/vhosts.default.conf
      - config/fingerprints.conf
      - static/

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

- [ ] **Step 2: Validate the GoReleaser config**

```bash
goreleaser check
```

Expected output: `• config is valid`

If `goreleaser` is not installed locally, install it:
```bash
go install github.com/goreleaser/goreleaser/v2@latest
```

- [ ] **Step 3: Commit**

```bash
git add .goreleaser.yaml
git commit -m "feat(docker): add GoReleaser Docker image and manifest config"
```

---

## Task 5: Extend `.goreleaser.yaml` — SBOM and signing

**Files:**
- Modify: `.goreleaser.yaml`

- [ ] **Step 1: Append `sboms:` and `docker_signs:` blocks to `.goreleaser.yaml`**

```yaml
sboms:
  - artifacts: binary

docker_signs:
  - cmd: cosign
    args:
      - sign
      - "--yes"
      - "${artifact}@${digest}"
    artifacts: all
```

`sboms:` uses `syft` (installed in CI — Task 6) to generate a CycloneDX SBOM per binary and attaches it to the GitHub Release.

`docker_signs:` runs `cosign sign` against every pushed image and manifest using keyless signing (OIDC identity from the GitHub Actions runner).

- [ ] **Step 2: Validate config**

```bash
goreleaser check
```

Expected: `• config is valid`

- [ ] **Step 3: Commit**

```bash
git add .goreleaser.yaml
git commit -m "feat(docker): add SBOM generation and cosign keyless signing"
```

---

## Task 6: Update `.github/workflows/release.yml`

**Files:**
- Modify: `.github/workflows/release.yml`

- [ ] **Step 1: Update `permissions` to add `id-token: write`**

Replace:
```yaml
permissions:
  contents: write
```

With:
```yaml
permissions:
  contents: write
  id-token: write
```

`id-token: write` is required for cosign keyless signing — it lets the job request an OIDC token from GitHub to use as the signing identity.

- [ ] **Step 2: Add three new steps before `Run GoReleaser`**

Insert after `Set up Go` and before `Run GoReleaser`:

```yaml
      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to Docker Hub
        uses: docker/login-action@v3
        with:
          username: ${{ secrets.DOCKERHUB_USERNAME }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}

      - name: Install syft
        uses: anchore/sbom-action/download-syft@v0

      - name: Install cosign
        uses: sigstore/cosign-installer@v3
```

- [ ] **Step 3: Verify the final workflow file looks like this**

```yaml
name: Release

on:
  push:
    tags:
      - '*'
permissions:
  contents: write
  id-token: write

jobs:
  goreleaser:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: '1.23'

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to Docker Hub
        uses: docker/login-action@v3
        with:
          username: ${{ secrets.DOCKERHUB_USERNAME }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}

      - name: Install syft
        uses: anchore/sbom-action/download-syft@v0

      - name: Install cosign
        uses: sigstore/cosign-installer@v3

      - name: Run GoReleaser
        uses: goreleaser/goreleaser-action@v5
        with:
          distribution: goreleaser
          version: '~> v2'
          args: release --clean
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "feat(docker): update release workflow for Docker Hub push and signing"
```

---

## Task 7: Smoke test with GoReleaser snapshot

This runs a full release build locally (no push, no tag required) to verify the entire pipeline works before the first real tag push.

**Prerequisite:** Docker must be running locally. GoReleaser must be installed.

- [ ] **Step 1: Run a snapshot release**

```bash
goreleaser release --snapshot --clean
```

`--snapshot` skips tag validation and publishing. `--clean` removes the `dist/` directory first.

Expected output (key lines to look for):
```
• starting release
• loading config file                    file=.goreleaser.yaml
• building binaries
• building docker images
• building docker manifests
• release succeeded
```

Docker images should appear locally. Verify:

```bash
docker images | grep tinyproxy
```

Expected: two images (`*-amd64` and `*-arm64` tagged with `0.0.0-SNAPSHOT-*`).

- [ ] **Step 2: Spot-check the amd64 image**

```bash
docker run --rm -p 8080:80 kalpadev/tinyproxy:0.0.0-SNAPSHOT-$(git rev-parse --short HEAD)-amd64
```

In another terminal:

```bash
curl -i http://localhost:8080/
```

Expected: HTTP response (200 or 301). Server did not crash.

- [ ] **Step 3: Remind yourself to add GitHub secrets before the first real release**

Two secrets are required in the GitHub repo settings (`Settings → Secrets and variables → Actions`):

| Secret name | Value |
|-------------|-------|
| `DOCKERHUB_USERNAME` | `kalpadev` |
| `DOCKERHUB_TOKEN` | A Docker Hub access token (create at https://hub.docker.com/settings/security — use "Access Token", not your password) |

- [ ] **Step 4: Final commit (if any loose files remain)**

```bash
git status
# If clean, nothing to do. If there are untracked files from the snapshot run, they should already be gitignored (dist/ is in .gitignore).
```

---

## Self-review notes

- **Spec coverage:** All spec sections covered — Dockerfile, Dockerfile.goreleaser, default config, goreleaser dockers/manifests/sboms/docker_signs, workflow permissions + steps, Docker Hub secrets.
- **No placeholders:** All code blocks are complete and executable.
- **Type consistency:** No function/type names across tasks — this is config/infrastructure only.
- **One open question for the implementer:** If `goreleaser release --snapshot` fails on Docker image signing (cosign won't be available locally unless installed), that's expected — signing only works in GitHub Actions with OIDC. The snapshot step will skip signing gracefully with a warning.
