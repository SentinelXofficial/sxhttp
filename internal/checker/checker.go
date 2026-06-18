package checker

import (
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

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
	"Go-http-client/1.1",
}

// StatusDescriptions maps HTTP status codes to human-readable descriptions.
var StatusDescriptions = map[int]string{
	200: "OK",
	201: "Created",
	204: "No Content",
	301: "Moved Permanently",
	302: "Found",
	304: "Not Modified",
	400: "Bad Request",
	401: "Unauthorized",
	403: "Forbidden",
	404: "Not Found",
	405: "Method Not Allowed",
	408: "Request Timeout",
	429: "Too Many Requests",
	500: "Internal Server Error",
	502: "Bad Gateway",
	503: "Service Unavailable",
	504: "Gateway Timeout",
}

// Result holds all scan data for a single URL.
type Result struct {
	URL           string   `json:"url"`
	Code          int      `json:"status_code"`
	Desc          string   `json:"status_desc"`
	Title         string   `json:"title,omitempty"`
	Tech          []string `json:"tech,omitempty"`
	CMSVersion    string   `json:"cms_version,omitempty"`
	WAF           string   `json:"waf,omitempty"`
	ResponseTime  int64    `json:"response_time_ms"`
	ContentLength int64    `json:"content_length"`
	Redirects     []string `json:"redirects,omitempty"`
	DefaultCred   string   `json:"default_cred,omitempty"`
	Error         string   `json:"error,omitempty"`
}

func randomUA() string {
	return userAgents[rand.Intn(len(userAgents))]
}

// NewHTTPClient creates an HTTP client that does not follow redirects automatically.
func NewHTTPClient(timeout int) *http.Client {
	return &http.Client{
		Timeout: time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// applyHeaders sets realistic browser-like headers on a request.
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

// doRequest performs a single GET request and returns the response, body, timing, and size.
func doRequest(client *http.Client, rawURL string, extra map[string]string) (*http.Response, string, int64, int64, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, "", 0, 0, err
	}
	applyHeaders(req, extra)

	start := time.Now()
	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return nil, "", elapsed, 0, err
	}

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 50*1024))
	resp.Body.Close()

	body := string(bodyBytes)
	size := resp.ContentLength
	if size < 0 {
		size = int64(len(bodyBytes))
	}
	return resp, body, elapsed, size, nil
}

// resolveURL resolves a possibly-relative Location header against the base URL.
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

// followRedirects traces the redirect chain for 3xx responses (up to 10 hops).
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

// CheckURL probes a URL (or tries https then http if no scheme given).
// It retries up to `retries` times on failure.
func CheckURL(client *http.Client, rawURL string, retries int, extra map[string]string) Result {
	rawURL = strings.TrimSpace(rawURL)

	var schemes []string
	if strings.HasPrefix(rawURL, "http://") || strings.HasPrefix(rawURL, "https://") {
		schemes = []string{rawURL}
	} else {
		schemes = []string{"https://" + rawURL, "http://" + rawURL}
	}

	for _, u := range schemes {
		var resp *http.Response
		var body string
		var elapsed, size int64
		var err error

		for attempt := 0; attempt <= retries; attempt++ {
			resp, body, elapsed, size, err = doRequest(client, u, extra)
			if err == nil {
				break
			}
			if attempt < retries {
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

		title := detect.Title(body)
		tech := detect.Tech(resp.Header, body)
		cmsVersion := detect.CMSVersion(body)
		waf := detect.WAF(resp.Header, resp.Header.Get("Server"))
		defCred := detect.DefaultCred(title, tech)

		var redirects []string
		if code >= 300 && code < 400 {
			redirects = followRedirects(client, u, extra)
		}

		return Result{
			URL:           u,
			Code:          code,
			Desc:          desc,
			Title:         title,
			Tech:          tech,
			CMSVersion:    cmsVersion,
			WAF:           waf,
			ResponseTime:  elapsed,
			ContentLength: size,
			Redirects:     redirects,
			DefaultCred:   defCred,
		}
	}

	return Result{URL: rawURL, Code: 0, Error: "connection failed"}
}
