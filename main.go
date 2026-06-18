package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SentinelXofficial/sxhttp/internal/banner"
	"github.com/SentinelXofficial/sxhttp/internal/checker"
	"github.com/SentinelXofficial/sxhttp/internal/color"
	"github.com/SentinelXofficial/sxhttp/internal/output"
	"github.com/SentinelXofficial/sxhttp/internal/updater"
)

func init() { rand.Seed(time.Now().UnixNano()) } //nolint:staticcheck

func main() {
	// ── Input ────────────────────────────────────────────────────────────────
	fileFlag  := flag.String("file", "", "Input file with URLs (one per line)")
	urlFlag   := flag.String("url", "", "Single URL to scan")

	// ── Request ──────────────────────────────────────────────────────────────
	threads     := flag.Int("threads", 10, "Concurrent workers")
	timeout     := flag.Int("timeout", 10, "Request timeout in seconds")
	retries     := flag.Int("retry", 0, "Retries on failure")
	rate        := flag.Int("rate", 0, "Max requests/second (0 = unlimited)")
	headersFlag := flag.String("header", "", "Custom headers: 'Key:Val;;Key2:Val2'")
	proxyFlag   := flag.String("proxy", "", "Proxy URL (http://host:port or socks5://host:port)")
	methodFlag  := flag.String("method", "GET", "HTTP method (GET, POST, HEAD, PUT, etc.)")
	bodyFlag    := flag.String("body", "", "Request body for POST/PUT")

	// ── Filter (status code) ─────────────────────────────────────────────────
	only    := flag.String("only", "", "Show only these status codes (e.g. 200,403)")
	exclude := flag.String("exclude", "", "Exclude these status codes (e.g. 404,301)")

	// ── Filter (body) ────────────────────────────────────────────────────────
	matchStr    := flag.String("match-str", "", "Show only responses containing string")
	matchRegex  := flag.String("match-regex", "", "Show only responses matching regex")
	filterStr   := flag.String("filter-str", "", "Exclude responses containing string")
	filterRegex := flag.String("filter-regex", "", "Exclude responses matching regex")

	// ── Probes ───────────────────────────────────────────────────────────────
	showIP      := flag.Bool("ip", false, "Resolve and show IP address")
	showTLS     := flag.Bool("tls", false, "Show TLS certificate info")
	showFavicon := flag.Bool("favicon", false, "Fetch favicon + mmh3 hash (Shodan pivot)")
	hashFlag    := flag.String("hash", "", "Hash response body: md5,sha256,mmh3")

	// ── Output ───────────────────────────────────────────────────────────────
	save      := flag.String("save", "", "Save matched URLs to file")
	saveJSON  := flag.String("json", "", "Save full results as JSON")
	saveCSV   := flag.String("csv", "", "Save full results as CSV")
	storeResp := flag.String("store-resp", "", "Directory to store raw response bodies")
	silent    := flag.Bool("silent", false, "Print matched URLs only (pipe-friendly)")

	// ── Display toggles ──────────────────────────────────────────────────────
	noWAF    := flag.Bool("no-waf", false, "Disable WAF detection")
	noTech   := flag.Bool("no-tech", false, "Disable tech stack detection")
	noTitle  := flag.Bool("no-title", false, "Disable title grabbing")
	noSize   := flag.Bool("no-size", false, "Disable content length display")
	showCred := flag.Bool("cred", false, "Show default credential hints")
	showRedir:= flag.Bool("redirect", false, "Show redirect chain for 3xx")

	// ── Misc ─────────────────────────────────────────────────────────────────
	updateFlag := flag.Bool("update", false, "Update sxhttp to latest version")
	flag.Parse()

	// ── Self-update ──────────────────────────────────────────────────────────
	if *updateFlag {
		updater.Update()
		return
	}

	// ── Validation ───────────────────────────────────────────────────────────
	fatalf := func(msg string) {
		fmt.Println(color.RED + "  [ERR] " + msg + color.RST)
		os.Exit(1)
	}
	if *threads <= 0 { fatalf("--threads must be > 0") }
	if *timeout <= 0 { fatalf("--timeout must be > 0") }
	if *retries < 0  { fatalf("--retry must be >= 0")  }
	if *rate < 0     { fatalf("--rate must be >= 0")   }

	// ── Compile regexes ──────────────────────────────────────────────────────
	var mRegex, fRegex *regexp.Regexp
	var err error
	if *matchRegex != "" {
		if mRegex, err = regexp.Compile(*matchRegex); err != nil {
			fatalf("invalid --match-regex: " + err.Error())
		}
	}
	if *filterRegex != "" {
		if fRegex, err = regexp.Compile(*filterRegex); err != nil {
			fatalf("invalid --filter-regex: " + err.Error())
		}
	}

	// ── Banner ───────────────────────────────────────────────────────────────
	if !*silent {
		banner.Print()
	}

	// ── Parse flags ──────────────────────────────────────────────────────────
	extraHeaders := parseHeaders(*headersFlag)
	onlyCodes, err := parseOnlyCodes(*only)
	if err != nil { fatalf(err.Error()) }
	excludeCodes, err := parseOnlyCodes(*exclude)
	if err != nil { fatalf(err.Error()) }

	hashTypes := []string{}
	if *hashFlag != "" {
		for _, h := range strings.Split(*hashFlag, ",") {
			hashTypes = append(hashTypes, strings.TrimSpace(h))
		}
	}

	// ── URLs ─────────────────────────────────────────────────────────────────
	urls := readURLs(*urlFlag, *fileFlag, fatalf)
	if len(urls) == 0 {
		fatalf("No URLs found")
	}

	// ── Print scan info ──────────────────────────────────────────────────────
	if !*silent {
		printScanInfo(scanInfoArgs{
			singleURL: *urlFlag, file: *fileFlag,
			urlCount: len(urls), threads: *threads, timeout: *timeout,
			retries: *retries, rate: *rate,
			method: *methodFlag, proxy: *proxyFlag,
			headersRaw: *headersFlag, only: *only, exclude: *exclude,
			matchStr: *matchStr, matchRegex: *matchRegex,
			filterStr: *filterStr, filterRegex: *filterRegex,
			hashFlag: *hashFlag,
			save: *save, saveJSON: *saveJSON, saveCSV: *saveCSV, storeResp: *storeResp,
			extraHeaders: extraHeaders,
		})
	}

	// ── HTTP client ──────────────────────────────────────────────────────────
	client := checker.NewHTTPClient(*timeout, *proxyFlag)

	// ── Rate limiter ─────────────────────────────────────────────────────────
	var rateLimiter <-chan time.Time
	if *rate > 0 {
		ticker := time.NewTicker(time.Second / time.Duration(*rate))
		defer ticker.Stop()
		rateLimiter = ticker.C
	}

	// ── Scan options ─────────────────────────────────────────────────────────
	scanOpts := checker.ScanOptions{
		Retries:      *retries,
		Method:       *methodFlag,
		Body:         *bodyFlag,
		ExtraHeaders: extraHeaders,
		ShowIP:       *showIP,
		TLSProbe:     *showTLS,
		FaviconProbe: *showFavicon,
		HashTypes:    hashTypes,
		MatchStr:     *matchStr,
		MatchRegex:   mRegex,
		FilterStr:    *filterStr,
		FilterRegex:  fRegex,
		StoreDir:     *storeResp,
	}

	// ── Worker pool ──────────────────────────────────────────────────────────
	jobs      := make(chan string, len(urls))
	resultsCh := make(chan checker.Result, len(urls))
	var wg sync.WaitGroup

	for i := 0; i < *threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range jobs {
				if rateLimiter != nil {
					<-rateLimiter
				}
				resultsCh <- checker.CheckURL(client, u, scanOpts)
			}
		}()
	}
	for _, u := range urls {
		jobs <- u
	}
	close(jobs)
	go func() { wg.Wait(); close(resultsCh) }()

	// ── Output config ────────────────────────────────────────────────────────
	outCfg := output.Config{
		Silent:      *silent,
		NoWAF:       *noWAF,
		NoTech:      *noTech,
		NoTitle:     *noTitle,
		NoSize:      *noSize,
		ShowCred:    *showCred,
		ShowRedir:   *showRedir,
		ShowIP:      *showIP,
		ShowTLS:     *showTLS,
		ShowFavicon: *showFavicon,
		ShowHash:    len(hashTypes) > 0,
		ShowMethod:  *methodFlag != "GET",
	}

	// ── Collect & display ────────────────────────────────────────────────────
	var results []checker.Result
	var saved   []string
	var mu      sync.Mutex
	startTime := time.Now()

	for r := range resultsCh {
		mu.Lock()
		results = append(results, r)
		mu.Unlock()

		if r.Code == 0 {
			if len(onlyCodes) == 0 {
				output.PrintResult(r, outCfg)
			}
			continue
		}

		// Status code filters
		if len(onlyCodes) > 0 && !contains(onlyCodes, r.Code) {
			continue
		}
		if len(excludeCodes) > 0 && contains(excludeCodes, r.Code) {
			continue
		}

		// Body match/filter
		if !r.Matched {
			continue
		}

		saved = append(saved, r.URL)
		output.PrintResult(r, outCfg)
	}

	elapsed := time.Since(startTime)

	// ── Save ─────────────────────────────────────────────────────────────────
	output.SaveURLs(*save, saved)
	output.SaveJSON(*saveJSON, results)
	output.SaveCSV(*saveCSV, results)

	if !*silent {
		output.PrintSummary(results, elapsed.Seconds(), *save, *saveJSON, *saveCSV, *storeResp)
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func readURLs(singleURL, file string, fatalf func(string)) []string {
	var urls []string
	switch {
	case singleURL != "" && file != "":
		fatalf("Use either --url or --file, not both")
	case singleURL != "":
		t := strings.TrimSpace(singleURL)
		if t == "" { fatalf("--url cannot be empty") }
		urls = append(urls, t)
	case file != "":
		f, err := os.Open(file)
		if err != nil { fatalf("Cannot open file: " + file) }
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") { continue }
			urls = append(urls, line)
		}
	default:
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			sc := bufio.NewScanner(os.Stdin)
			for sc.Scan() {
				line := strings.TrimSpace(sc.Text())
				if line == "" || strings.HasPrefix(line, "#") { continue }
				urls = append(urls, line)
			}
		} else {
			fmt.Println(color.RED + "  [ERR] --url or --file required, or pipe URLs via stdin" + color.RST)
			fmt.Println(color.GRY + "  Usage: sxhttp --url https://example.com" + color.RST)
			fmt.Println(color.GRY + "         sxhttp --file urls.txt --only 200" + color.RST)
			fmt.Println(color.GRY + "         cat urls.txt | sxhttp --only 200" + color.RST)
			fmt.Println()
			os.Exit(1)
		}
	}
	return urls
}

func parseOnlyCodes(s string) ([]int, error) {
	var codes []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" { continue }
		n, err := strconv.Atoi(p)
		if err != nil { return nil, fmt.Errorf("invalid status code: %s", p) }
		codes = append(codes, n)
	}
	return codes, nil
}

func contains(codes []int, code int) bool {
	for _, c := range codes {
		if c == code { return true }
	}
	return false
}

func parseHeaders(raw string) map[string]string {
	headers := map[string]string{}
	if raw == "" { return headers }
	for _, h := range strings.Split(raw, ";;") {
		parts := strings.SplitN(strings.TrimSpace(h), ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return headers
}

type scanInfoArgs struct {
	singleURL, file string
	urlCount, threads, timeout, retries, rate int
	method, proxy, headersRaw string
	only, exclude string
	matchStr, matchRegex, filterStr, filterRegex string
	hashFlag string
	save, saveJSON, saveCSV, storeResp string
	extraHeaders map[string]string
}

func printScanInfo(a scanInfoArgs) {
	src := a.file
	if a.singleURL != "" { src = a.singleURL } else if src == "" { src = "stdin" }

	p := func(label, val string) {
		if val == "" { return }
		fmt.Printf(color.GRY+"  %-12s: %s%s%s\n"+color.RST, label, color.BOLD, val, color.RST)
	}
	p("Target",   src)
	p("URLs",     strconv.Itoa(a.urlCount))
	p("Threads",  strconv.Itoa(a.threads))
	p("Timeout",  strconv.Itoa(a.timeout)+"s")
	p("Method",   a.method)
	p("Proxy",    a.proxy)
	if a.retries > 0    { p("Retry",    strconv.Itoa(a.retries)) }
	if a.rate > 0       { p("Rate",     strconv.Itoa(a.rate)+"/s") }
	if len(a.extraHeaders) > 0 { p("Headers", a.headersRaw) }
	p("Filter",   a.only)
	p("Exclude",  a.exclude)
	p("Match-str",   a.matchStr)
	p("Match-regex", a.matchRegex)
	p("Filter-str",  a.filterStr)
	p("Filter-regex",a.filterRegex)
	p("Hash",     a.hashFlag)
	p("Output",   a.save)
	p("JSON",     a.saveJSON)
	p("CSV",      a.saveCSV)
	p("Store-resp",   a.storeResp)

	fmt.Println()
	fmt.Println(color.GRY + color.DIM + "  " + strings.Repeat("-", 70) + color.RST)
	fmt.Println()
}
