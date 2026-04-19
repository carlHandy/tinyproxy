#!/usr/bin/env python3
"""nginx → tinyproxy config converter (standalone, no tinyproxy install required).

Usage:
    pip install crossplane
    python nginx-migrate.py nginx.conf [--output vhosts.conf] [--report migration-report.md]
"""

import argparse
import sys
from datetime import datetime, timezone

try:
    import crossplane
except ImportError:
    print("error: crossplane not installed. Run: pip install crossplane", file=sys.stderr)
    sys.exit(1)

DOCS_BASE = "https://tinyproxy.io/docs/migration/nginx-gap-analysis"

UNSUPPORTED = {
    "location":              ("No URL routing in tinyproxy", "url-routing"),
    "rewrite":               ("URL rewriting not supported", "rewrites"),
    "map":                   ("map directive not supported", "map"),
    "if":                    ("if blocks not supported", "conditionals"),
    "try_files":             ("try_files not supported", "try-files"),
    "return":                ("Redirects (return) not supported", "redirects"),
    "error_page":            ("Custom error pages not supported", "error-pages"),
    "auth_basic":            ("HTTP basic auth not supported", "auth-basic"),
    "auth_basic_user_file":  ("HTTP basic auth not supported", "auth-basic"),
    "auth_request":          ("auth_request not supported", "auth-request"),
    "limit_conn":            ("Connection limiting not supported", "limit-conn"),
    "limit_conn_zone":       ("Connection limiting not supported", "limit-conn"),
    "proxy_set_header":      ("Request header manipulation not supported", "proxy-set-header"),
    "proxy_hide_header":     ("Response header manipulation not supported", "proxy-set-header"),
    "proxy_read_timeout":    ("Upstream timeouts not supported", "timeouts"),
    "proxy_send_timeout":    ("Upstream timeouts not supported", "timeouts"),
    "proxy_connect_timeout": ("Upstream timeouts not supported", "timeouts"),
    "access_log":            ("Per-vhost logging config not supported", "logging"),
    "error_log":             ("Per-vhost logging config not supported", "logging"),
    "geo":                   ("geo module not supported", "geo"),
    "sub_filter":            ("sub_filter not supported", "sub-filter"),
    "mirror":                ("mirror not supported", "mirror"),
    "stream":                ("stream blocks not supported", "stream"),
    "mail":                  ("mail blocks not supported", "mail"),
    "health_check":          ("nginx Plus active health_check not supported", "health-check-plus"),
    "auth_jwt":              ("nginx Plus JWT auth not supported", "jwt"),
    "js_include":            ("njs not supported", "njs"),
    "js_content":            ("njs not supported", "njs"),
}

SILENT = {
    "server_name", "listen", "tcp_nopush", "tcp_nodelay", "keepalive_timeout",
    "sendfile", "types", "include", "default_type", "worker_processes",
    "worker_connections", "events", "pid", "user", "proxy_buffering",
    "proxy_buffer_size", "proxy_buffers",
}

SECURITY_HEADERS = {
    "x-frame-options":          "frame_options",
    "x-content-type-options":   "content_type",
    "x-xss-protection":         "xss_protection",
    "content-security-policy":  "csp",
    "strict-transport-security": "hsts",
}


def parse_listen_args(args):
    port, ssl = 80, False
    if not args:
        return port, ssl
    for a in args[1:]:
        if a == "ssl":
            ssl = True
    addr = args[0]
    if ":" in addr:
        addr = addr.rsplit(":", 1)[-1].rstrip("]")
    try:
        port = int(addr)
    except ValueError:
        port = 80
    return port, ssl


def upstream_name(proxy_pass):
    u = proxy_pass
    for prefix in ("http://", "https://"):
        if u.startswith(prefix):
            u = u[len(prefix):]
            break
    if ":" not in u and "/" not in u and u:
        return u
    return ""


def convert_body_size(s):
    if s == "0":
        return ""
    u = s.upper().strip()
    if u.endswith("G"):
        return u[:-1] + "GB"
    if u.endswith("M"):
        return u[:-1] + "MB"
    if u.endswith("K"):
        return u[:-1] + "KB"
    return u + "B"


def parse_limit_req_zone(args):
    zone_name, requests, window = None, None, None
    for a in args:
        if a.startswith("zone="):
            zone_name = a[5:].split(":")[0]
        if a.startswith("rate="):
            val = a[5:].replace("r/", "")
            if val.endswith("m"):
                requests, window = int(val[:-1]), "1m"
            elif val.endswith("s"):
                requests, window = int(val[:-1]), "1s"
    if zone_name and requests is not None:
        return zone_name, {"requests": requests, "window": window}
    return None, None


def resolve_limit_req(args, zones):
    for a in args:
        if a.startswith("zone="):
            name = a[5:]
            if name in zones:
                return zones[name]
    return None


def directive_to_raw(d):
    args_str = " ".join(d.get("args", []))
    if d.get("block") is not None:
        return f"{d['directive']} {args_str} {{ ... }}"
    return f"{d['directive']} {args_str};"


def convert_upstream_block(block):
    uc = {"strategy": "round_robin", "backends": [], "stubs": []}
    for d in block:
        name = d["directive"]
        args = d.get("args", [])
        if name == "server" and args:
            addr = args[0]
            if "://" not in addr:
                addr = "http://" + addr
            backend = addr
            for a in args[1:]:
                if a.startswith("weight="):
                    backend += " weight " + a[7:]
            uc["backends"].append(backend)
        elif name == "ip_hash":
            uc["strategy"] = "ip_hash"
        elif name == "least_conn":
            uc["strategy"] = "least_conn"
        elif name in ("keepalive", "keepalive_requests", "keepalive_time"):
            uc["stubs"].append({
                "tag": name, "raw": directive_to_raw(d),
                "reason": "Upstream keepalive not configurable in tinyproxy",
                "anchor": "upstream-keepalive",
            })
        elif name in UNSUPPORTED:
            reason, anchor = UNSUPPORTED[name]
            uc["stubs"].append({"tag": name, "raw": directive_to_raw(d), "reason": reason, "anchor": anchor})
    return uc


def convert_server_block(block, upstreams, rate_zones, http_gzip, report):
    vh = {
        "hostname": "default", "port": 0, "root": "", "proxy_pass": "",
        "ssl": None, "compression": http_gzip, "security": {},
        "fastcgi": None, "upstream": None, "max_body_size": "",
        "stubs": [],
    }

    def add_stub(d, reason, anchor):
        vh["stubs"].append({"tag": d["directive"], "raw": directive_to_raw(d), "reason": reason, "anchor": anchor})
        report["stubbed"] += 1
        report["entries"].append({
            "vhost": vh["hostname"], "directive": d["directive"],
            "file": d.get("file", ""), "line": d.get("line", 0), "reason": reason,
        })

    for d in block:
        n, args = d["directive"], d.get("args", [])
        if n == "server_name" and args and vh["hostname"] == "default":
            vh["hostname"] = args[0]
        elif n == "listen":
            port, ssl = parse_listen_args(args)
            if vh["port"] == 0:
                vh["port"] = port
            if ssl and vh["ssl"] is None:
                vh["ssl"] = {"cert": "", "key": ""}

    for d in block:
        n, args = d["directive"], d.get("args", [])
        if n in ("server_name", "listen"):
            report["converted"] += 1
        elif n == "root" and args:
            vh["root"] = args[0]
            report["converted"] += 1
        elif n == "proxy_pass" and args:
            target = args[0]
            name = upstream_name(target)
            if name and name in upstreams:
                uc = convert_upstream_block(upstreams[name])
                vh["stubs"].extend(uc.pop("stubs", []))
                vh["upstream"] = uc
            else:
                vh["proxy_pass"] = target
            report["converted"] += 1
        elif n == "ssl_certificate" and args:
            if vh["ssl"] is None:
                vh["ssl"] = {"cert": "", "key": ""}
            vh["ssl"]["cert"] = args[0]
            report["converted"] += 1
        elif n == "ssl_certificate_key" and args:
            if vh["ssl"] is None:
                vh["ssl"] = {"cert": "", "key": ""}
            vh["ssl"]["key"] = args[0]
            report["converted"] += 1
        elif n == "gzip" and args:
            vh["compression"] = args[0]
            report["converted"] += 1
        elif n == "client_max_body_size" and args:
            vh["max_body_size"] = convert_body_size(args[0])
            report["converted"] += 1
        elif n == "add_header" and len(args) >= 2:
            hdr = args[0].lower()
            val = " ".join(args[1:]).strip('"')
            if hdr in SECURITY_HEADERS:
                vh["security"][SECURITY_HEADERS[hdr]] = val
                report["converted"] += 1
            else:
                add_stub(d, "Non-security add_header not supported", "add-header")
        elif n == "limit_req":
            rl = resolve_limit_req(args, rate_zones)
            if rl:
                vh["security"]["rate_requests"] = rl["requests"]
                vh["security"]["rate_window"] = rl["window"]
                report["converted"] += 1
            else:
                add_stub(d, "Could not resolve rate limit zone", "rate-limiting")
        elif n == "fastcgi_pass" and args:
            if vh["fastcgi"] is None:
                vh["fastcgi"] = {"pass": "", "index": "", "params": []}
            vh["fastcgi"]["pass"] = args[0]
            report["converted"] += 1
        elif n == "fastcgi_index" and args:
            if vh["fastcgi"] is None:
                vh["fastcgi"] = {"pass": "", "index": "", "params": []}
            vh["fastcgi"]["index"] = args[0]
            report["converted"] += 1
        elif n == "fastcgi_param" and len(args) >= 2:
            if vh["fastcgi"] is None:
                vh["fastcgi"] = {"pass": "", "index": "", "params": []}
            vh["fastcgi"]["params"].append(f"{args[0]} {args[1]}")
            report["converted"] += 1
        elif n not in SILENT:
            if n in UNSUPPORTED:
                reason, anchor = UNSUPPORTED[n]
                add_stub(d, reason, anchor)

    return vh


def convert_nginx_file(filename):
    try:
        payload = crossplane.parse(filename, combine=True)
    except Exception as e:
        raise RuntimeError(f"parse error: {e}")

    if not payload.get("config"):
        raise RuntimeError(f"no config found in {filename}")

    report = {
        "source": filename,
        "generated": datetime.now(timezone.utc),
        "converted": 0,
        "stubbed": 0,
        "entries": [],
    }
    vhosts = []
    parsed = payload["config"][0].get("parsed", [])

    upstreams = {}
    rate_zones = {}
    http_gzip = ""
    http_block = []

    for d in parsed:
        if d["directive"] == "http":
            http_block = d.get("block", [])

    for d in http_block:
        n = d["directive"]
        if n == "upstream" and d.get("args"):
            upstreams[d["args"][0]] = d.get("block", [])
        elif n == "limit_req_zone":
            name, rl = parse_limit_req_zone(d.get("args", []))
            if name:
                rate_zones[name] = rl
        elif n == "gzip" and d.get("args"):
            http_gzip = d["args"][0]

    for d in http_block:
        if d["directive"] == "server":
            vh = convert_server_block(d.get("block", []), upstreams, rate_zones, http_gzip, report)
            vhosts.append(vh)

    return vhosts, report


def render_vhost_conf(vhosts):
    lines = ["vhosts {"]
    for vh in vhosts:
        lines.append(f"    {vh['hostname']} {{")
        if vh["port"]:
            lines.append(f"        port {vh['port']}")
        if vh["root"]:
            lines.append(f"        root {vh['root']}")
        if vh["proxy_pass"]:
            lines.append(f"        proxy_pass {vh['proxy_pass']}")
        if vh["compression"]:
            lines.append(f"        compression {vh['compression']}")
        if vh["max_body_size"]:
            lines.append(f"        max_body_size {vh['max_body_size']}")
        if vh["ssl"] and (vh["ssl"]["cert"] or vh["ssl"]["key"]):
            lines.append("        ssl {")
            if vh["ssl"]["cert"]:
                lines.append(f"            cert {vh['ssl']['cert']}")
            if vh["ssl"]["key"]:
                lines.append(f"            key {vh['ssl']['key']}")
            lines.append("        }")
        sec = vh.get("security", {})
        if sec:
            lines.append("        security {")
            for k in ("frame_options", "content_type"):
                v = sec.get(k)
                if v:
                    lines.append(f"            {k} {v}")
            for k in ("xss_protection", "csp", "hsts"):
                v = sec.get(k)
                if v:
                    lines.append(f'            {k} "{v}"')
            if sec.get("rate_requests"):
                lines.append("            rate_limit {")
                lines.append(f"                requests {sec['rate_requests']}")
                lines.append(f"                window {sec['rate_window']}")
                lines.append("            }")
            lines.append("        }")
        fc = vh.get("fastcgi")
        if fc:
            lines.append("        fastcgi {")
            if fc["pass"]:
                lines.append(f"            pass {fc['pass']}")
            if fc["index"]:
                lines.append(f"            index {fc['index']}")
            for p in fc["params"]:
                lines.append(f"            param {p}")
            lines.append("        }")
        uc = vh.get("upstream")
        if uc:
            lines.append("        upstream {")
            lines.append(f"            strategy {uc['strategy']}")
            for b in uc["backends"]:
                lines.append(f"            backend {b}")
            lines.append("        }")
        for s in vh.get("stubs", []):
            lines.append("")
            lines.append(f"        # UNSUPPORTED[{s['tag']}]: {s['raw']}")
            lines.append(f"        # → {s['reason']}")
            lines.append(f"        # → See: {DOCS_BASE}#{s['anchor']}")
        lines.append("    }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def render_report(vhosts, report):
    lines = [
        "# Migration Report — nginx → tinyproxy",
        "",
        f"Generated: {report['generated'].strftime('%Y-%m-%d %H:%M:%S UTC')}",
        "",
        "## Summary",
        "",
        "| | |",
        "|---|---|",
        f"| Source | `{report['source']}` |",
        f"| Virtual hosts converted | {len(vhosts)} |",
        f"| Directives converted | {report['converted']} |",
        f"| Directives stubbed (unsupported) | {report['stubbed']} |",
        "",
    ]
    if report["entries"]:
        lines += [
            "## Unsupported Directives",
            "",
            "| Virtual Host | Directive | File | Line | Reason |",
            "|---|---|---|---|---|",
        ]
        for e in report["entries"]:
            lines.append(f"| {e['vhost']} | `{e['directive']}` | {e['file']} | {e['line']} | {e['reason']} |")
        lines.append("")
    lines += [
        "## Next Steps",
        "",
        "1. Review `# UNSUPPORTED` stubs in the generated `vhosts.conf`",
        f"2. See [Gap Analysis & Roadmap]({DOCS_BASE}) for implementation plans",
        "3. Test your config: `ENV=dev go run ./cmd/tinyproxy/`",
    ]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(
        description="Convert nginx config to tinyproxy vhosts.conf",
        epilog="Requires: pip install crossplane",
    )
    parser.add_argument("nginx_conf", help="Path to nginx.conf")
    parser.add_argument("--output", default="vhosts.conf", help="Output vhosts.conf path (default: vhosts.conf)")
    parser.add_argument("--report", default="migration-report.md", help="Output report path (default: migration-report.md)")
    args = parser.parse_args()

    try:
        vhosts, report = convert_nginx_file(args.nginx_conf)
    except RuntimeError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    conf = render_vhost_conf(vhosts)
    with open(args.output, "w") as f:
        f.write(conf)

    rpt = render_report(vhosts, report)
    with open(args.report, "w") as f:
        f.write(rpt)

    print(f"Converted {len(vhosts)} vhost(s), {report['converted']} directive(s) migrated, {report['stubbed']} stubbed.")
    print(f"Config written to: {args.output}")
    print(f"Report written to: {args.report}")
    if report["stubbed"] > 0:
        print(f"\nReview {report['stubbed']} unsupported directive(s) — see {DOCS_BASE}")


if __name__ == "__main__":
    main()
