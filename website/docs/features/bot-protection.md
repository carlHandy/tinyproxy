# Bot & AI Protection

**tinyproxy** includes native middleware to protect your applications from automated scanners, scrapers, and AI crawlers.

## Enabling Bot Protection

Bot protection is opt-in per virtual host. Enable it using the `bot_protection` block:

```text
vhosts {
    example.com {
        proxy_pass http://backend:8080
        bot_protection {
            enabled        true
            block_scanners true
            honeypot       true
        }
    }
}
```

## Features

### Scanner Blocking
When `block_scanners` is `true`, **tinyproxy** intercepts requests to known vulnerability-scanning paths, such as:
- `/.env`
- `/.git`
- `/wp-admin`
- `/phpMyAdmin`
- `/actuator`

It handles URL-encoded variants and path normalization tricks automatically.

### Honeypot Mode
If `honeypot` is `true`, instead of returning a 403 Forbidden, **tinyproxy** serves convincing fake content tailored to the requested path (e.g., a fake `.env` file with bogus credentials). It also adds a random delay (150–750 ms) to slow down automated tools.

### AI Crawler Blocking
By default, enabling bot protection blocks popular AI crawlers and scrapers:
- **AI Crawlers**: GPTBot, ClaudeBot, CCBot, PerplexityBot, anthropic-ai, etc.
- **SEO Bots**: AhrefsBot, SemrushBot, DotBot.
- **Scrapers**: python-requests, Scrapy, libwww-perl.

## Customization

### Blocking Extra Paths
```text
bot_protection {
    enabled    true
    block_path /my-secret-admin
    block_path /debug
}
```

### Blocking/Allowing User Agents
```text
bot_protection {
    enabled true
    block   "MyCustomScraper"
    allow   "FriendlyPartnerBot"
}
```

## Built-in Allowed Agents
The following are always permitted, even if they match block rules:
- Googlebot, bingbot, DuckDuckBot, Baiduspider, facebookexternalhit, Twitterbot, LinkedInBot, Applebot.
