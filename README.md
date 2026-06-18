# sxhttp

**SentinelX HTTP** — Fast, concurrent web status checker with WAF detection, tech fingerprinting, and redirect tracing.

> Part of the [SentinelX](https://github.com/SentinelXofficial) ecosystem.

## Install

```bash
go install github.com/SentinelXofficial/sxhttp@latest
```

## Usage

```bash
# Single URL
sxhttp --url https://example.com

# File input
sxhttp --file urls.txt --threads 20 --only 200,403

# Pipe from stdin
cat urls.txt | sxhttp --only 200 --silent

# Save results
sxhttp --file urls.txt --save alive.txt --json results.json --csv results.csv

# Show redirect chain + default cred hints
sxhttp --url https://example.com --redirect --cred

# Custom headers (WAF bypass attempt)
sxhttp --file urls.txt --header "X-Forwarded-For:127.0.0.1;;X-Real-IP:127.0.0.1"

# Rate limiting
sxhttp --file urls.txt --rate 10 --threads 5

# Update to latest
sxhttp --update
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--url` | — | Single URL to scan |
| `--file` | — | File with URLs (one per line) |
| `--threads` | 10 | Concurrent workers |
| `--timeout` | 10 | Request timeout (seconds) |
| `--retry` | 0 | Retries on failure |
| `--only` | — | Show only these codes (e.g. `200,403`) |
| `--exclude` | — | Skip these codes (e.g. `404,301`) |
| `--rate` | 0 | Max requests/second (0 = unlimited) |
| `--header` | — | Custom headers: `Key:Val;;Key2:Val2` |
| `--save` | — | Save matched URLs to text file |
| `--json` | — | Save full results as JSON |
| `--csv` | — | Save full results as CSV |
| `--silent` | false | Print URLs only (pipe-friendly) |
| `--no-waf` | false | Disable WAF detection |
| `--no-tech` | false | Disable tech stack detection |
| `--no-title` | false | Disable title grabbing |
| `--no-size` | false | Disable content length |
| `--cred` | false | Show default credential hints |
| `--redirect` | false | Show redirect chain for 3xx |
| `--update` | false | Self-update to latest release |

## Project Structure

```
sxhttp/
├── main.go                  # Entry point, CLI flags, worker pool
├── go.mod
├── internal/
│   ├── color/color.go       # ANSI color constants + helpers
│   ├── version/version.go   # Version constant + repo path
│   ├── updater/updater.go   # GitHub release check + self-update
│   ├── banner/banner.go     # ASCII banner + version display
│   ├── detect/detect.go     # WAF, tech, CMS, title detection
│   ├── checker/checker.go   # HTTP client + URL probing logic
│   └── output/output.go     # Result printing + file saving
```

## Author

**WildanDev** — [@SentinelXofficial](https://github.com/SentinelXofficial)
