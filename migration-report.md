# Migration Report — nginx → tinyproxy

Generated: 2026-04-19 22:38:39 UTC

## Summary

| | |
|---|---|
| Source | `/tmp/test-nginx.conf` |
| Virtual hosts converted | 1 |
| Directives converted | 3 |
| Directives stubbed (unsupported) | 1 |

## Unsupported Directives

| Virtual Host | Directive | File | Line | Reason |
|---|---|---|---|---|
| example.com | `location` |  | 7 | No URL routing in tinyproxy |

## Next Steps

1. Review `# UNSUPPORTED` stubs in the generated `vhosts.conf`
2. See [Gap Analysis & Roadmap](https://tinyproxy.io/docs/migration/nginx-gap-analysis) for implementation plans
3. Test your config: `ENV=dev go run ./cmd/tinyproxy/`
