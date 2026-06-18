package output

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/SentinelXofficial/sxhttp/internal/checker"
	"github.com/SentinelXofficial/sxhttp/internal/color"
	"github.com/SentinelXofficial/sxhttp/internal/detect"
)

// Config holds display toggles passed from CLI flags.
type Config struct {
	Silent    bool
	NoWAF     bool
	NoTech    bool
	NoTitle   bool
	NoSize    bool
	ShowCred  bool
	ShowRedir bool
}

// PrintResult prints a single scan result to stdout.
func PrintResult(r checker.Result, cfg Config) {
	if r.Code == 0 {
		if !cfg.Silent {
			fmt.Printf("  %s  %-20s  %-10s  %s\n",
				color.GRY+"[---]"+color.RST,
				color.GRY+"connection-failed"+color.RST,
				color.GRY+"---"+color.RST,
				color.GRY+r.URL+color.RST,
			)
		}
		return
	}

	if cfg.Silent {
		fmt.Println(r.URL)
		return
	}

	wafLabel := ""
	if !cfg.NoWAF && r.WAF != "" {
		wafLabel = "  " + color.MAG + "[" + r.WAF + "]" + color.RST
	}

	techLabel := ""
	if !cfg.NoTech && len(r.Tech) > 0 {
		t := make([]string, len(r.Tech))
		copy(t, r.Tech)
		if r.CMSVersion != "" {
			for _, p := range detect.CMSVersionPatterns() {
				for i, tech := range t {
					if strings.HasPrefix(r.CMSVersion, p.Name) && tech == p.Name {
						t[i] = r.CMSVersion
					}
				}
			}
		}
		techLabel = "  " + color.CYN + "[" + strings.Join(t, ", ") + "]" + color.RST
	}

	titleLabel := ""
	if !cfg.NoTitle && r.Title != "" {
		titleLabel = "  " + color.GRY + color.DIM + "\"" + r.Title + "\"" + color.RST
	}

	sizeLabel := ""
	if !cfg.NoSize {
		sizeLabel = "  " + color.Size(r.ContentLength)
	}

	fmt.Printf("  [%s]  %-20s  %-10s%s  %s%s%s%s\n",
		color.Status(r.Code),
		color.GRY+r.Desc+color.RST,
		color.RT(r.ResponseTime),
		sizeLabel,
		r.URL,
		wafLabel,
		techLabel,
		titleLabel,
	)

	if cfg.ShowRedir && len(r.Redirects) > 0 {
		for _, redir := range r.Redirects {
			fmt.Printf("       "+color.GRY+color.DIM+"↳ %s"+color.RST+"\n", redir)
		}
	}

	if cfg.ShowCred && r.DefaultCred != "" {
		fmt.Printf("       "+color.YEL+"[CRED] %s"+color.RST+"\n", r.DefaultCred)
	}
}

// PrintSummary prints the final scan statistics.
func PrintSummary(results []checker.Result, elapsed float64, save, saveJSON, saveCSV string) {
	var s200, s3xx, s4xx, s5xx, sErr int
	for _, r := range results {
		switch {
		case r.Code >= 200 && r.Code < 300:
			s200++
		case r.Code >= 300 && r.Code < 400:
			s3xx++
		case r.Code >= 400 && r.Code < 500:
			s4xx++
		case r.Code >= 500:
			s5xx++
		default:
			sErr++
		}
	}

	fmt.Println()
	fmt.Println(color.GRY + color.DIM + "  " + strings.Repeat("-", 70) + color.RST)
	fmt.Println()
	fmt.Printf("  "+color.BOLD+"Scan complete"+color.RST+color.GRY+"  %d URLs  //  %.2fs\n"+color.RST, len(results), elapsed)
	fmt.Println()
	fmt.Printf("  "+color.GRN+"2xx"+color.RST+color.GRY+"  %-6d"+color.RST, s200)
	fmt.Printf("  "+color.BLU+"3xx"+color.RST+color.GRY+"  %-6d"+color.RST, s3xx)
	fmt.Printf("  "+color.YEL+"4xx"+color.RST+color.GRY+"  %-6d"+color.RST, s4xx)
	fmt.Printf("  "+color.RED+"5xx"+color.RST+color.GRY+"  %-6d"+color.RST, s5xx)
	fmt.Printf("  "+color.GRY+"err  %-6d"+color.RST, sErr)
	fmt.Println()

	if save != "" {
		fmt.Printf("\n  "+color.GRY+"Saved URLs to %s%s\n"+color.RST, color.BOLD+save, color.RST)
	}
	if saveJSON != "" {
		fmt.Printf("  "+color.GRY+"JSON saved to %s%s\n"+color.RST, color.BOLD+saveJSON, color.RST)
	}
	if saveCSV != "" {
		fmt.Printf("  "+color.GRY+"CSV saved to %s%s\n"+color.RST, color.BOLD+saveCSV, color.RST)
	}
	fmt.Println()
}

// SaveURLs writes matched URLs to a plain text file.
func SaveURLs(path string, urls []string) {
	if path == "" || len(urls) == 0 {
		return
	}
	f, err := os.Create(path)
	if err != nil {
		fmt.Println(color.RED + "\n  [ERR] Cannot create output file: " + path + color.RST)
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, u := range urls {
		fmt.Fprintln(w, u)
	}
	w.Flush()
}

// SaveJSON writes all results to a JSON file.
func SaveJSON(path string, results []checker.Result) {
	if path == "" {
		return
	}
	f, err := os.Create(path)
	if err != nil {
		fmt.Println(color.RED + "\n  [ERR] Cannot create JSON file: " + path + color.RST)
		return
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.Encode(results)
}

// SaveCSV writes all results to a CSV file.
func SaveCSV(path string, results []checker.Result) {
	if path == "" {
		return
	}
	f, err := os.Create(path)
	if err != nil {
		fmt.Println(color.RED + "\n  [ERR] Cannot create CSV file: " + path + color.RST)
		return
	}
	defer f.Close()
	w := csv.NewWriter(f)
	w.Write([]string{
		"url", "status_code", "status_desc", "title",
		"tech", "cms_version", "waf",
		"response_time_ms", "content_length",
		"redirects", "default_cred",
	})
	for _, r := range results {
		w.Write([]string{
			r.URL,
			strconv.Itoa(r.Code),
			r.Desc,
			r.Title,
			strings.Join(r.Tech, "|"),
			r.CMSVersion,
			r.WAF,
			strconv.FormatInt(r.ResponseTime, 10),
			strconv.FormatInt(r.ContentLength, 10),
			strings.Join(r.Redirects, " | "),
			r.DefaultCred,
		})
	}
	w.Flush()
}
