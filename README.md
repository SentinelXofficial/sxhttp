# sxhttp

**SentinelX HTTP** — Fast, concurrent web status checker with WAF detection, tech fingerprinting, TLS inspection, favicon hashing, and proxy support.

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

# TLS info + IP + favicon hash (Shodan pivot)
sxhttp --url https://example.com --tls --ip --favicon

# Hash response body
sxhttp --file urls.txt --hash md5,sha256,mmh3

# Through Burp proxy
sxhttp --file urls.txt --proxy http://127.0.0.1:8080

# Through SOCKS5 proxy
sxhttp --file urls.txt --proxy socks5://127.0.0.1:1080

# POST request
sxhttp --url https://example.com/api --method POST --body '{"test":1}' --header "Content-Type:application/json"

# Match/filter by body content
sxhttp --file urls.txt --match-str "admin"
sxhttp --file urls.txt --match-regex "(?i)(dashboard|panel|admin)"
sxhttp --file urls.txt --filter-str "404 Not Found"

# Store all response bodies
sxhttp --file urls.txt --only 200 --store-resp ./responses/

# Save results
sxhttp --file urls.txt --save alive.txt --json results.json --csv results.csv

# Show redirect chain + default cred hints
sxhttp --url https://example.com --redirect --cred

# Update to latest
sxhttp --update
```

## Flags

### Input
| Flag | Default | Description |
|------|---------|-------------|
| `--url` | — | Single URL to scan |
| `--file` | — | File with URLs (one per line) |

### Request
| Flag | Default | Description |
|------|---------|-------------|
| `--threads` | 10 | Concurrent workers |
| `--timeout` | 10 | Request timeout (seconds) |
| `--retry` | 0 | Retries on failure |
| `--rate` | 0 | Max requests/second (0 = unlimited) |
| `--method` | GET | HTTP method (GET, POST, HEAD, PUT, etc.) |
| `--body` | — | Request body for POST/PUT |
| `--header` | — | Custom headers: `Key:Val;;Key2:Val2` |
| `--proxy` | — | Proxy URL (`http://host:port` or `socks5://host:port`) |

### Filter (status code)
| Flag | Default | Description |
|------|---------|-------------|
| `--only` | — | Show only these codes (e.g. `200,403`) |
| `--exclude` | — | Skip these codes (e.g. `404,301`) |

### Filter (body)
| Flag | Default | Description |
|------|---------|-------------|
| `--match-str` | — | Show only responses containing string |
| `--match-regex` | — | Show only responses matching regex |
| `--filter-str` | — | Exclude responses containing string |
| `--filter-regex` | — | Exclude responses matching regex |

### Probes
| Flag | Default | Description |
|------|---------|-------------|
| `--ip` | false | Resolve and show IP address |
| `--tls` | false | Show TLS version, cipher, CN, expiry, SANs |
| `--favicon` | false | Fetch favicon + mmh3 hash (Shodan: `http.favicon.hash`) |
| `--hash` | — | Hash response body: `md5,sha256,mmh3` |

### Output
| Flag | Default | Description |
|------|---------|-------------|
| `--save` | — | Save matched URLs to text file |
| `--json` | — | Save full results as JSON |
| `--csv` | — | Save full results as CSV |
| `--store-resp` | — | Directory to store raw response bodies |
| `--silent` | false | Print URLs only (pipe-friendly) |
| `--no-waf` | false | Disable WAF detection |
| `--no-tech` | false | Disable tech stack detection |
| `--no-title` | false | Disable title grabbing |
| `--no-size` | false | Disable content length display |
| `--cred` | false | Show default credential hints |
| `--redirect` | false | Show redirect chain for 3xx |
| `--update` | false | Self-update to latest release |

## Project Structure

```
sxhttp/
├── main.go                    # Entry point, CLI flags, worker pool
├── go.mod
├── internal/
│   ├── color/color.go         # ANSI color constants + helpers
│   ├── version/version.go     # Version constant + repo path
│   ├── updater/updater.go     # GitHub release check + self-update
│   ├── banner/banner.go       # ASCII banner + version display
│   ├── detect/
│   │   ├── detect.go          # WAF, tech stack, CMS, title detection
│   │   ├── hash.go            # MD5, SHA256, MurmurHash3, favicon hash
│   │   └── tls.go             # TLS certificate info extraction
│   ├── checker/checker.go     # HTTP client, proxy, URL probing logic
│   └── output/output.go       # Result printing + file saving (JSON/CSV/txt)
```

## Author

**WildanDev** — [@SentinelXofficial](https://github.com/SentinelXofficial)
