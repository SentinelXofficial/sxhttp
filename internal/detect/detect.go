package detect

import (
	"net/http"
	"regexp"
	"strings"
)

// WAF header signatures
var wafSignatures = map[string]string{
	"cloudflare":     "Cloudflare",
	"cf-ray":         "Cloudflare",
	"x-sucuri-id":    "Sucuri",
	"x-sucuri-cache": "Sucuri",
	"x-fw-protect":   "Wordfence",
	"x-cdn":          "CDN",
	"x-akamai":       "Akamai",
	"x-amz-cf-id":    "AWS CloudFront",
	"x-azure-ref":    "Azure CDN",
	"x-ddos-guard":   "DDoS-Guard",
	"x-protected-by": "WAF",
}

// Tech stack signatures (header or body match)
var techSignatures = []struct {
	Header string
	Value  string
	Body   string
	Name   string
}{
	{Header: "x-powered-by", Value: "php", Name: "PHP"},
	{Header: "x-powered-by", Value: "asp.net", Name: "ASP.NET"},
	{Header: "x-powered-by", Value: "express", Name: "Express.js"},
	{Header: "server", Value: "apache", Name: "Apache"},
	{Header: "server", Value: "nginx", Name: "Nginx"},
	{Header: "server", Value: "iis", Name: "IIS"},
	{Header: "server", Value: "litespeed", Name: "LiteSpeed"},
	{Header: "x-generator", Value: "wordpress", Name: "WordPress"},
	{Body: "wp-content/themes", Name: "WordPress"},
	{Body: "wp-content/plugins", Name: "WordPress"},
	{Body: "drupal.js", Name: "Drupal"},
	{Body: "joomla", Name: "Joomla"},
	{Body: "laravel", Name: "Laravel"},
	{Body: "codeigniter", Name: "CodeIgniter"},
	{Body: "symfony", Name: "Symfony"},
	{Body: "django", Name: "Django"},
	{Body: "react", Name: "React"},
	{Body: "vue.js", Name: "Vue.js"},
	{Body: "angular", Name: "Angular"},
	{Header: "set-cookie", Value: "phpsessid", Name: "PHP"},
	{Header: "set-cookie", Value: "asp.net_sessionid", Name: "ASP.NET"},
	{Header: "set-cookie", Value: "laravel_session", Name: "Laravel"},
}

// CMSVersionPattern is exported so output package can use it for label rewriting
type CMSVersionPattern struct {
	Name    string
	Pattern *regexp.Regexp
}

var cmsVersionPatterns = []CMSVersionPattern{
	{"WordPress", regexp.MustCompile(`(?i)<meta name="generator" content="WordPress ([0-9.]+)"`)},
	{"Drupal", regexp.MustCompile(`(?i)Drupal ([0-9.]+)`)},
	{"Joomla", regexp.MustCompile(`(?i)<meta name="generator" content="Joomla! ([0-9.]+)"`)},
	{"Laravel", regexp.MustCompile(`(?i)laravel/([0-9.]+)`)},
}

// Default credential hints per CMS/panel
var defaultCreds = map[string]string{
	"cPanel":      "admin:admin | root:root",
	"WordPress":   "admin:admin | admin:password",
	"Laravel":     "admin@example.com:password",
	"CodeIgniter": "admin:admin",
	"phpMyAdmin":  "root:(empty) | root:root",
}

var titleRegex = regexp.MustCompile(`(?i)<title[^>]*>([^<]{1,200})</title>`)

// WAF detects WAF provider from response headers and server string.
func WAF(headers http.Header, server string) string {
	serverLower := strings.ToLower(server)
	if strings.Contains(serverLower, "cloudflare") {
		return "Cloudflare"
	}
	if strings.Contains(serverLower, "ddos-guard") {
		return "DDoS-Guard"
	}
	for h, waf := range wafSignatures {
		if headers.Get(h) != "" {
			return waf
		}
	}
	return ""
}

// Tech detects technology stack from headers and body.
func Tech(headers http.Header, body string) []string {
	seen := map[string]bool{}
	var techs []string
	bodyLower := strings.ToLower(body)

	for _, sig := range techSignatures {
		if seen[sig.Name] {
			continue
		}
		if sig.Header != "" {
			val := strings.ToLower(headers.Get(sig.Header))
			if val != "" && (sig.Value == "" || strings.Contains(val, sig.Value)) {
				seen[sig.Name] = true
				techs = append(techs, sig.Name)
				continue
			}
		}
		if sig.Body != "" && strings.Contains(bodyLower, sig.Body) {
			seen[sig.Name] = true
			techs = append(techs, sig.Name)
		}
	}
	return techs
}

// CMSVersion tries to extract a CMS name + version string from body.
func CMSVersion(body string) string {
	for _, p := range cmsVersionPatterns {
		match := p.Pattern.FindStringSubmatch(body)
		if len(match) > 1 {
			return p.Name + " " + match[1]
		}
	}
	return ""
}

// CMSVersionPatterns returns patterns for external use (e.g. output label rewriting).
func CMSVersionPatterns() []CMSVersionPattern {
	return cmsVersionPatterns
}

// Title extracts and truncates the HTML <title> tag content.
func Title(body string) string {
	match := titleRegex.FindStringSubmatch(body)
	if len(match) > 1 {
		title := strings.TrimSpace(match[1])
		title = strings.ReplaceAll(title, "\n", " ")
		title = strings.ReplaceAll(title, "\r", "")
		if len(title) > 60 {
			title = title[:57] + "..."
		}
		return title
	}
	return ""
}

// DefaultCred returns a credential hint based on page title or detected tech.
func DefaultCred(title string, techs []string) string {
	titleLower := strings.ToLower(title)
	if strings.Contains(titleLower, "cpanel") {
		return defaultCreds["cPanel"]
	}
	if strings.Contains(titleLower, "phpmyadmin") {
		return defaultCreds["phpMyAdmin"]
	}
	for _, tech := range techs {
		if cred, ok := defaultCreds[tech]; ok {
			return cred
		}
	}
	return ""
}
