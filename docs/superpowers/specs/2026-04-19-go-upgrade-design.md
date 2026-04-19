# Go 1.26.2 Upgrade — Design Spec

**Date:** 2026-04-19  
**Status:** Approved

## Overview

Bump the project's Go version from 1.25.0 to 1.26.2 across all version-pinning files.

## Files Modified

| File | Change |
|---|---|
| `go.mod` | `go 1.25.0` → `go 1.26.2` |
| `.github/workflows/release.yml` | `go-version: '1.23'` → `go-version: '1.26.2'` |

## Post-edit verification

1. `go mod tidy` — updates toolchain directive and checksums in `go.sum`
2. `go build ./...` — confirms the project compiles at the new version
3. `go test ./...` — confirms no regressions
