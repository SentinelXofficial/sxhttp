package checker

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/proxy"

	"github.com/SentinelXofficial/sxhttp/internal/detect"
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
	"Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/124.0.0.0 Mobile Safari/537.36",
	"curl/8.7.1",
	"python-requests/2.31.0",
}

// StatusDescriptions maps HTTP status codes to descriptions.
var StatusDescriptions = map[int]string{
	200: "OK", 201: "Created", 204: "No Content",
	301: "Moved Permanently", 302: "Found", 304: "Not Modified",
	400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
	404: "Not Found", 405: "Method Not Allowed", 408: "Request Timeout",
	429: "Too Many Requests", 500: "Internal Server Error",
	502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout",
}

// ScanOptions holds per-request options.
type ScanOptions struct {
	Retries      int
	Method       string
	Body         string
	ExtraHeaders map[string]string
	ShowIP       bool
	TLSProbe     bool
	FaviconProbe bool
	HashTypes    []string // "md5", "sha256", "mmh3"
	MatchStr     string
	MatchRegex   *regexp.Regexp
	FilterStr    string
	FilterRegex  *regexp.Regexp
	StoreDir     string
}

// Result holds all scan data for a single URL.
type Result struct {
	URL           string            `json:"url"`
	Code          int               `json:"status_code"`
	Desc          string            `json:"status_desc"`
	Method        string            `json:"method,omitempty"`
	Title         string            `json:"title,omitempty"`
	Tech          []string          `json:"tech,omitempty"`
	CMSVersion    string            `json:"cms_version,omitempty"`
	WAF           string            `json:"waf,omitempty"`
	IP            string            `json:"ip,omitempty"`
	TLS           *detect.TLSInfo   `json:"tls,omitempty"`
	Hashes        map[string]string `json:"hashes,omitempty"`
	FaviconHash   string            `json:"favicon_hash,omitempty"`
	ResponseTime  int64             `json:"response_time_ms"`
	ContentLength int64             `json:"content_length"`
	Redirects     []string          `json:"redirects,omitempty"`
	DefaultCred   string            `json:"default_cred,omitempty"`
	Matched       bool              `json:"-"`
	Error         string            `json:"error,omitempty"`
}

// NewHTTPClient creates an HTTP client with optional proxy support.
// Supports http://, https://, and socks5:// proxy URLs.
func NewHTTPClient(timeout int, proxyURL string) *http.Client {
	transport := &http.Transport{
		DisableKeepAlives:   false,
		MaxIdleConnsPerHost: 10,
	}

	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err == nil {
			if u.Scheme == "socks5" || u.Scheme == "socks5h" {
				var auth *proxy.Auth
				if u.User != nil {
					pass, _ := u.User.Password()
					auth = &proxy.Auth{User: u.User.Username(), Password: pass}
				}
				host := u.Host
				dialer, err := proxy.SOCKS5("tcp", host, auth, proxy.Direct)
				if err == nil {
					transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
						return dialer.Dial(network, addr)
					}
				}
			} else {
				transport.Proxy = http.ProxyURL(u)
			}
		}
	}

	return &http.Client{
		Timeout:   time.Duration(timeout) * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func randomUA() string { return userAgents[rand.Intn(len(userAgents))] }

// applyHeaders sets realistic browser-like headers.
func applyHeaders(req *http.Request, extra map[string]string) {
	req.Header.Set("User-Agent", randomUA())
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Cache-Control", "max-age=0")
	for k, v := range extra {
		req.Header.Set(k, v)
	}
}

// doRequest performs a single HTTP request, returns response + body + timing.
func doRequest(client *http.Client, rawURL, method, body string, extra map[string]string) (*http.Response, string, []byte, int64, int64, error) {
	if method == "" {
		method = "GET"
	}
	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequest(method, rawURL, bodyReader)
	if err != nil {
		return nil, "", nil, 0, 0, err
	}
	applyHeaders(req, extra)

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return nil, "", nil, elapsed, 0, err
	}

	rawBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 50*1024))
	resp.Body.Close()

	bodyStr := string(rawBytes)
	size := resp.ContentLength
	if size < 0 {
		size = int64(len(rawBytes))
	}
	return resp, bodyStr, rawBytes, elapsed, size, nil
}

// resolveIP resolves the IP address of a URL's host.
func resolveIP(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return ""
	}
	return addrs[0]
}

// resolveURL resolves a possibly-relative Location against a base URL.
func resolveURL(baseURL, location string) (string, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	loc, err := url.Parse(location)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(loc).String(), nil
}

// followRedirects traces the redirect chain for 3xx responses.
func followRedirects(client *http.Client, startURL string, extra map[string]string) []string {
	var chain []string
	current := startURL
	seen := map[string]bool{}
	for i := 0; i < 10; i++ {
		if seen[current] {
			break
		}
		seen[current] = true
		req, err := http.NewRequest("GET", current, nil)
		if err != nil {
			break
		}
		applyHeaders(req, extra)
		resp, err := client.Do(req)
		if err != nil {
			break
		}
		resp.Body.Close()
		code := resp.StatusCode
		if code >= 300 && code < 400 {
			loc := strings.TrimSpace(resp.Header.Get("Location"))
			if loc == "" {
				break
			}
			next, err := resolveURL(current, loc)
			if err != nil {
				break
			}
			chain = append(chain, fmt.Sprintf("%d → %s", code, next))
			current = next
		} else {
			break
		}
	}
	return chain
}

// fetchFavicon tries to find and download the favicon for a page.
// It checks <link rel="icon"> in body first, then falls back to /favicon.ico.
func fetchFavicon(client *http.Client, pageURL, body string) []byte {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}

	// Try to find favicon URL in HTML
	faviconURL := ""
	bodyLower := strings.ToLower(body)
	for _, candidate := range []string{`rel="icon"`, `rel='icon'`, `rel="shortcut icon"`, `rel='shortcut icon'`} {
		idx := strings.Index(bodyLower, candidate)
		if idx == -1 {
			continue
		}
		// look for href="..." near the match
		chunk := body[max(0, idx-100) : min(len(body), idx+200)]
		hrefIdx := strings.Index(strings.ToLower(chunk), "href=")
		if hrefIdx == -1 {
			continue
		}
		after := chunk[hrefIdx+5:]
		quote := byte('"')
		if len(after) > 0 && after[0] == '\'' {
			quote = '\''
		}
		if len(after) > 1 {
			after = after[1:]
		}
		end := strings.IndexByte(after, quote)
		if end > 0 {
			faviconURL = strings.TrimSpace(after[:end])
			break
		}
	}

	// Resolve relative URL or fall back to /favicon.ico
	if faviconURL == "" {
		faviconURL = base.Scheme + "://" + base.Host + "/favicon.ico"
	} else {
		loc, err := url.Parse(faviconURL)
		if err == nil {
			faviconURL = base.ResolveReference(loc).String()
		}
	}

	req, err := http.NewRequest("GET", faviconURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", randomUA())
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		return nil
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 100*1024))
	return data
}

// storeResponse saves the raw response body to a directory.
func storeResponse(dir, rawURL string, code int, body string) {
	if dir == "" || body == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	safe := strings.NewReplacer(
		"://", "_", "/", "_", ":", "_",
		"?", "_", "&", "_", "=", "_", ".", "_",
	).Replace(rawURL)
	if len(safe) > 180 {
		safe = safe[:180]
	}
	filename := filepath.Join(dir, fmt.Sprintf("%d_%s.txt", code, safe))
	os.WriteFile(filename, []byte(body), 0o644)
}

// matchesFilters checks match/filter criteria against a response body.
// Returns true if the result should be kept.
func matchesFilters(body string, opts ScanOptions) bool {
	// If any match criteria set, body must match at least one
	hasMatch := opts.MatchStr != "" || opts.MatchRegex != nil
	if hasMatch {
		strMatch := opts.MatchStr != "" && strings.Contains(body, opts.MatchStr)
		regexMatch := opts.MatchRegex != nil && opts.MatchRegex.MatchString(body)
		if !strMatch && !regexMatch {
			return false
		}
	}
	// Filter criteria: exclude if body matches
	if opts.FilterStr != "" && strings.Contains(body, opts.FilterStr) {
		return false
	}
	if opts.FilterRegex != nil && opts.FilterRegex.MatchString(body) {
		return false
	}
	return true
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// CheckURL probes a URL with all configured options.
func CheckURL(client *http.Client, rawURL string, opts ScanOptions) Result {
	rawURL = strings.TrimSpace(rawURL)

	var schemes []string
	if strings.HasPrefix(rawURL, "http://") || strings.HasPrefix(rawURL, "https://") {
		schemes = []string{rawURL}
	} else {
		schemes = []string{"https://" + rawURL, "http://" + rawURL}
	}

	method := opts.Method
	if method == "" {
		method = "GET"
	}

	for _, u := range schemes {
		var resp *http.Response
		var bodyStr string
		var rawBytes []byte
		var elapsed, size int64
		var err error

		for attempt := 0; attempt <= opts.Retries; attempt++ {
			resp, bodyStr, rawBytes, elapsed, size, err = doRequest(client, u, method, opts.Body, opts.ExtraHeaders)
			if err == nil {
				break
			}
			if attempt < opts.Retries {
				time.Sleep(500 * time.Millisecond)
			}
		}
		if err != nil {
			continue
		}

		code := resp.StatusCode
		desc := StatusDescriptions[code]
		if desc == "" {
			desc = "Unknown"
		}

		title := detect.Title(bodyStr)
		tech := detect.Tech(resp.Header, bodyStr)
		cmsVersion := detect.CMSVersion(bodyStr)
		waf := detect.WAF(resp.Header, resp.Header.Get("Server"))
		defCred := detect.DefaultCred(title, tech)

		var redirects []string
		if code >= 300 && code < 400 {
			redirects = followRedirects(client, u, opts.ExtraHeaders)
		}

		// ── IP resolution ────────────────────────────────────────
		ip := ""
		if opts.ShowIP {
			ip = resolveIP(u)
		}

		// ── TLS info ─────────────────────────────────────────────
		var tlsInfo *detect.TLSInfo
		if opts.TLSProbe {
			tlsInfo = detect.ExtractTLS(resp)
		}

		// ── Body hashing ─────────────────────────────────────────
		hashes := detect.ComputeHashes(rawBytes, opts.HashTypes)

		// ── Favicon hash ─────────────────────────────────────────
		faviconHash := ""
		if opts.FaviconProbe {
			favData := fetchFavicon(client, u, bodyStr)
			if len(favData) > 0 {
				faviconHash = detect.FaviconHash(favData)
			}
		}

		// ── Match / filter ───────────────────────────────────────
		matched := matchesFilters(bodyStr, opts)

		// ── Store response ───────────────────────────────────────
		if opts.StoreDir != "" {
			storeResponse(opts.StoreDir, u, code, bodyStr)
		}

		return Result{
			URL:           u,
			Code:          code,
			Desc:          desc,
			Method:        method,
			Title:         title,
			Tech:          tech,
			CMSVersion:    cmsVersion,
			WAF:           waf,
			IP:            ip,
			TLS:           tlsInfo,
			Hashes:        hashes,
			FaviconHash:   faviconHash,
			ResponseTime:  elapsed,
			ContentLength: size,
			Redirects:     redirects,
			DefaultCred:   defCred,
			Matched:       matched,
		}
	}

	return Result{URL: rawURL, Code: 0, Error: "connection failed"}
}
