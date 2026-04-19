# Go 1.26.2 Upgrade — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bump Go from 1.25.0 to 1.26.2 in every version-pinning location in the repo.

**Architecture:** Two config edits — the module directive in `go.mod` and the CI toolchain pin in `.github/workflows/release.yml` — followed by `go mod tidy` to refresh the toolchain directive and `go.sum`.

**Tech Stack:** Go 1.26.2, GitHub Actions `actions/setup-go@v5`.

---

## File Map

| Action | Path |
|---|---|
| Modify | `go.mod` |
| Modify | `.github/workflows/release.yml` |

---

## Task 1: Bump `go.mod`

**Files:**
- Modify: `go.mod`

- [ ] **Step 1: Update the `go` directive**

Open `go.mod`. Change:
```
go 1.25.0
```
to:
```
go 1.26.2
```

- [ ] **Step 2: Run `go mod tidy`**

```bash
go mod tidy
```

Expected: exits 0. `go.mod` will gain or update a `toolchain go1.26.2` line; `go.sum` may gain new entries.

- [ ] **Step 3: Build to confirm compilation**

```bash
go build ./...
```

Expected: exits 0 with no output.

- [ ] **Step 4: Run tests**

```bash
go test ./...
```

Expected: all packages `ok`, none `FAIL`.

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum
git commit -m "chore(go): upgrade Go toolchain to 1.26.2"
```

---

## Task 2: Bump CI workflow

**Files:**
- Modify: `.github/workflows/release.yml`

- [ ] **Step 1: Update `go-version`**

In `.github/workflows/release.yml`, change:
```yaml
        go-version: '1.23'
```
to:
```yaml
        go-version: '1.26.2'
```

- [ ] **Step 2: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "ci: pin Go 1.26.2 in release workflow"
```
