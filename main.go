package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"os"
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

func init() {
	rand.Seed(time.Now().UnixNano()) //nolint:staticcheck
}

func main() {
	// ── Flags ────────────────────────────────────────────────────────────────
	fileFlag    := flag.String("file", "", "Input file with URLs (one per line)")
	urlFlag     := flag.String("url", "", "Single URL to scan")
	threads     := flag.Int("threads", 10, "Concurrent workers")
	timeout     := flag.Int("timeout", 10, "Request timeout in seconds")
	retries     := flag.Int("retry", 0, "Retries on failure")
	only        := flag.String("only", "", "Only show these status codes (e.g. 200,403)")
	exclude     := flag.String("exclude", "", "Exclude these status codes (e.g. 404,301)")
	save        := flag.String("save", "", "Save matched URLs to file")
	saveJSON    := flag.String("json", "", "Save full results as JSON")
	saveCSV     := flag.String("csv", "", "Save full results as CSV")
	silent      := flag.Bool("silent", false, "Only print URLs, no banner or summary")
	noWAF       := flag.Bool("no-waf", false, "Disable WAF detection")
	noTech      := flag.Bool("no-tech", false, "Disable tech detection")
	noTitle     := flag.Bool("no-title", false, "Disable title grabbing")
	noSize      := flag.Bool("no-size", false, "Disable content length display")
	showCred    := flag.Bool("cred", false, "Show default credential hints")
	showRedir   := flag.Bool("redirect", false, "Show redirect chain for 3xx")
	rate        := flag.Int("rate", 0, "Max requests/second (0 = unlimited)")
	headersFlag := flag.String("header", "", "Custom headers: 'Key:Val;;Key2:Val2'")
	updateFlag  := flag.Bool("update", false, "Update sxhttp to latest version")
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
	if *threads <= 0  { fatalf("--threads must be > 0") }
	if *timeout <= 0  { fatalf("--timeout must be > 0") }
	if *retries < 0   { fatalf("--retry must be >= 0")  }
	if *rate < 0      { fatalf("--rate must be >= 0")   }

	// ── Banner ───────────────────────────────────────────────────────────────
	if !*silent {
		banner.Print()
	}

	// ── Headers ──────────────────────────────────────────────────────────────
	extraHeaders := parseHeaders(*headersFlag)

	// ── Status filters ───────────────────────────────────────────────────────
	onlyCodes, err := parseOnlyCodes(*only)
	if err != nil { fatalf(err.Error()) }
	excludeCodes, err := parseOnlyCodes(*exclude)
	if err != nil { fatalf(err.Error()) }

	// ── URL input ────────────────────────────────────────────────────────────
	urls := readURLs(*urlFlag, *fileFlag, fatalf)
	if len(urls) == 0 {
		fatalf("No URLs found")
	}

	// ── Print scan info ──────────────────────────────────────────────────────
	if !*silent {
		printScanInfo(*urlFlag, *fileFlag, len(urls), *threads, *timeout,
			*retries, *rate, *headersFlag, *only, *exclude,
			*save, *saveJSON, *saveCSV, extraHeaders)
	}

	// ── Worker pool ──────────────────────────────────────────────────────────
	client := checker.NewHTTPClient(*timeout)

	var rateLimiter <-chan time.Time
	if *rate > 0 {
		ticker := time.NewTicker(time.Second / time.Duration(*rate))
		defer ticker.Stop()
		rateLimiter = ticker.C
	}

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
				resultsCh <- checker.CheckURL(client, u, *retries, extraHeaders)
			}
		}()
	}
	for _, u := range urls {
		jobs <- u
	}
	close(jobs)
	go func() { wg.Wait(); close(resultsCh) }()

	// ── Collect & display ────────────────────────────────────────────────────
	outCfg := output.Config{
		Silent:    *silent,
		NoWAF:     *noWAF,
		NoTech:    *noTech,
		NoTitle:   *noTitle,
		NoSize:    *noSize,
		ShowCred:  *showCred,
		ShowRedir: *showRedir,
	}

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
		if len(onlyCodes) > 0 && !contains(onlyCodes, r.Code) {
			continue
		}
		if len(excludeCodes) > 0 && contains(excludeCodes, r.Code) {
			continue
		}

		saved = append(saved, r.URL)
		output.PrintResult(r, outCfg)
	}

	elapsed := time.Since(startTime)

	// ── Save outputs ─────────────────────────────────────────────────────────
	output.SaveURLs(*save, saved)
	output.SaveJSON(*saveJSON, results)
	output.SaveCSV(*saveCSV, results)

	if !*silent {
		output.PrintSummary(results, elapsed.Seconds(), *save, *saveJSON, *saveCSV)
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
		if t == "" {
			fatalf("--url cannot be empty")
		}
		urls = append(urls, t)

	case file != "":
		f, err := os.Open(file)
		if err != nil {
			fatalf("Cannot open file: " + file)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			urls = append(urls, line)
		}

	default:
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
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
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid status code: %s", p)
		}
		codes = append(codes, n)
	}
	return codes, nil
}

func contains(codes []int, code int) bool {
	for _, c := range codes {
		if c == code {
			return true
		}
	}
	return false
}

func parseHeaders(raw string) map[string]string {
	headers := map[string]string{}
	if raw == "" {
		return headers
	}
	for _, h := range strings.Split(raw, ";;") {
		parts := strings.SplitN(strings.TrimSpace(h), ":", 2)
		if len(parts) == 2 {
			headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return headers
}

func printScanInfo(
	singleURL, file string,
	urlCount, threads, timeout, retries, rate int,
	headersRaw, only, exclude, save, saveJSON, saveCSV string,
	extraHeaders map[string]string,
) {
	src := file
	if singleURL != "" {
		src = singleURL
	} else if src == "" {
		src = "stdin"
	}

	p := func(label, val string) {
		fmt.Printf(color.GRY+"  %-9s: %s%s%s\n"+color.RST, label, color.BOLD, val, color.RST)
	}
	p("Target",  src)
	p("URLs",    strconv.Itoa(urlCount))
	p("Threads", strconv.Itoa(threads))
	p("Timeout", strconv.Itoa(timeout)+"s")
	if retries > 0   { p("Retry",   strconv.Itoa(retries)) }
	if rate > 0      { p("Rate",    strconv.Itoa(rate)+"/s") }
	if len(extraHeaders) > 0 { p("Headers", headersRaw) }
	if only != ""    { p("Filter",  only) }
	if exclude != "" { p("Exclude", exclude) }
	if save != ""    { p("Output",  save) }
	if saveJSON != "" { p("JSON",   saveJSON) }
	if saveCSV != ""  { p("CSV",    saveCSV) }

	fmt.Println()
	fmt.Println(color.GRY + color.DIM + "  " + strings.Repeat("-", 70) + color.RST)
	fmt.Println()
}
