// Command certwatch checks the TLS certificates of one or more hosts and
// reports how many days each has left before it expires.
//
// Exit codes: 0 when every certificate is OK, 1 when any host is expired,
// critical, warning, or unreachable, 2 on a usage error.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Abrar892/go-certwatch/internal/certcheck"
)

const version = "1.0.0"

func main() {
	var (
		warnDays     = flag.Int("warn-days", 30, "expiry within this many days is a warning")
		criticalDays = flag.Int("critical-days", 7, "expiry within this many days is critical")
		timeout      = flag.Duration("timeout", 10*time.Second, "per-host dial timeout")
		concurrency  = flag.Int("concurrency", 10, "maximum concurrent checks")
		hostsFile    = flag.String("file", "", "file with one host per line")
		jsonOut      = flag.Bool("json", false, "print results as JSON")
		showVersion  = flag.Bool("version", false, "print version and exit")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] host [host ...]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Check TLS certificate expiry for one or more hosts.")
		fmt.Fprintln(os.Stderr, "Hosts may be given as example.com, example.com:8443, or https://example.com.")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		flag.PrintDefaults()
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("certwatch %s\n", version)
		return
	}

	if *warnDays <= *criticalDays || *criticalDays < 0 {
		fmt.Fprintln(os.Stderr, "error: -warn-days must be greater than -critical-days, and -critical-days must be >= 0")
		os.Exit(2)
	}
	if *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "error: -timeout must be positive")
		os.Exit(2)
	}

	hosts := flag.Args()
	if *hostsFile != "" {
		fromFile, err := certcheck.ParseHostsFile(*hostsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot read hosts file: %v\n", err)
			os.Exit(2)
		}
		hosts = append(hosts, fromFile...)
	}
	if len(hosts) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	ctx := context.Background()
	opts := certcheck.Options{
		WarnDays:     *warnDays,
		CriticalDays: *criticalDays,
		Timeout:      *timeout,
	}
	results := certcheck.CheckMany(ctx, hosts, opts, *concurrency)

	// Deterministic output: alphabetical by host, then port.
	sort.Slice(results, func(i, j int) bool {
		if results[i].Host != results[j].Host {
			return results[i].Host < results[j].Host
		}
		return results[i].Port < results[j].Port
	})

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(results); err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot encode output: %v\n", err)
			os.Exit(2)
		}
	} else {
		printTable(results)
	}

	worst := certcheck.StatusOK
	for _, r := range results {
		if r.Status > worst {
			worst = r.Status
		}
	}
	if worst != certcheck.StatusOK {
		os.Exit(1)
	}
}

func printTable(results []certcheck.Result) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "HOST\tEXPIRES\tDAYS LEFT\tISSUER\tSTATUS")
	for _, r := range results {
		host := r.Host
		if r.Port != "443" {
			host += ":" + r.Port
		}
		if r.Status == certcheck.StatusError {
			fmt.Fprintf(w, "%s\t-\t-\t-\t%s: %s\n", host, r.Status, r.Error)
			continue
		}
		issuer := r.Issuer
		if issuer == "" {
			issuer = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n",
			host, r.NotAfter.Format("2006-01-02"), r.DaysLeft, issuer, r.Status)
	}
	w.Flush()

	var counts [5]int
	for _, r := range results {
		counts[r.Status]++
	}
	var parts []string
	for s, label := range map[certcheck.Status]string{
		certcheck.StatusOK:       "ok",
		certcheck.StatusWarning:  "warning",
		certcheck.StatusCritical: "critical",
		certcheck.StatusExpired:  "expired",
		certcheck.StatusError:    "error",
	} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], label))
		}
	}
	fmt.Printf("\n%s\n", strings.Join(parts, ", "))
}
