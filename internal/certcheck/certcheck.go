// Package certcheck inspects TLS certificates served by remote hosts and
// reports how long each certificate has left before it expires.
//
// The check deliberately does not validate the certificate chain: the goal
// is expiry reporting, not trust verification, so a self-signed or expired
// certificate is still reported (with its real expiry date) instead of
// failing the handshake.
package certcheck

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"math"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// Status describes the health of a certificate at check time.
type Status int

const (
	// StatusOK means the certificate is comfortably inside its lifetime.
	StatusOK Status = iota
	// StatusWarning means the certificate expires within the warning window.
	StatusWarning
	// StatusCritical means the certificate expires within the critical window.
	StatusCritical
	// StatusExpired means the certificate is already past its NotAfter date.
	StatusExpired
	// StatusError means the certificate could not be fetched at all.
	StatusError
)

// String renders the status as a short human-readable label.
func (s Status) String() string {
	switch s {
	case StatusOK:
		return "OK"
	case StatusWarning:
		return "WARNING"
	case StatusCritical:
		return "CRITICAL"
	case StatusExpired:
		return "EXPIRED"
	default:
		return "ERROR"
	}
}

// Result is the outcome of checking one host.
type Result struct {
	Host     string    `json:"host"`
	Port     string    `json:"port"`
	Subject  string    `json:"subject,omitempty"`
	Issuer   string    `json:"issuer,omitempty"`
	SANs     []string  `json:"sans,omitempty"`
	NotAfter time.Time `json:"not_after,omitempty"`
	// DaysLeft is whole days until expiry, negative when expired.
	DaysLeft int    `json:"days_left"`
	Status   Status `json:"status"`
	// Error is set when the certificate could not be fetched.
	Error string `json:"error,omitempty"`
}

// Options tunes a check.
type Options struct {
	// WarnDays: expiry within this many days is a warning.
	WarnDays int
	// CriticalDays: expiry within this many days is critical.
	CriticalDays int
	// Timeout bounds a single host's dial + handshake.
	Timeout time.Duration
}

// DefaultOptions returns the conventional thresholds: warn at 30 days,
// critical at 7 days, 10 seconds per host.
func DefaultOptions() Options {
	return Options{WarnDays: 30, CriticalDays: 7, Timeout: 10 * time.Second}
}

// DaysUntil returns whole days from now until t, rounded down. A certificate
// expiring in 5 days and 23 hours reports 5 days left; one that expired an
// hour ago reports -1.
func DaysUntil(t, now time.Time) int {
	return int(math.Floor(t.Sub(now).Hours() / 24))
}

// Classify maps an expiry date to a status against the given thresholds.
// warnDays must be greater than criticalDays; callers validate this.
func Classify(notAfter, now time.Time, warnDays, criticalDays int) Status {
	days := DaysUntil(notAfter, now)
	switch {
	case days < 0:
		return StatusExpired
	case days <= criticalDays:
		return StatusCritical
	case days <= warnDays:
		return StatusWarning
	default:
		return StatusOK
	}
}

// ParseHost normalises a user-supplied host spec into a host and port.
// It accepts "example.com", "example.com:8443", "https://example.com",
// and bracketed IPv6 forms. The port defaults to 443.
func ParseHost(input string) (host, port string, err error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", "", fmt.Errorf("empty host")
	}
	// Strip a scheme if one was given, e.g. "https://example.com/path".
	if strings.Contains(input, "://") {
		u, uerr := url.Parse(input)
		if uerr != nil {
			return "", "", fmt.Errorf("invalid host %q: %w", input, uerr)
		}
		input = u.Host
	} else {
		// Drop any trailing path or query the user pasted in.
		if i := strings.IndexAny(input, "/?#"); i >= 0 {
			input = input[:i]
		}
	}
	host, port, splitErr := net.SplitHostPort(input)
	if splitErr != nil {
		// No port present: the whole input is the host.
		host, port = input, "443"
	}
	if host == "" {
		return "", "", fmt.Errorf("empty host in %q", input)
	}
	host = strings.Trim(host, "[]")
	return host, port, nil
}

// Check fetches the leaf certificate served by host and classifies it.
// host may be any form ParseHost accepts. The returned Result always has
// Host, Port and Status set, even on failure.
func Check(ctx context.Context, host string, opts Options) Result {
	h, p, err := ParseHost(host)
	if err != nil {
		return Result{Host: host, Port: p, Status: StatusError, Error: err.Error()}
	}
	res := Result{Host: h, Port: p}

	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: opts.Timeout},
		Config: &tls.Config{
			// Expiry reporting, not trust validation: accept any chain so
			// expired and self-signed certificates are still reported.
			InsecureSkipVerify: true,
			ServerName:         h,
		},
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(h, p))
	if err != nil {
		res.Status = StatusError
		res.Error = err.Error()
		return res
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		res.Status = StatusError
		res.Error = "connection is not a TLS connection"
		return res
	}
	certs := tlsConn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		res.Status = StatusError
		res.Error = "server presented no certificate"
		return res
	}
	leaf := certs[0]
	res.Subject = leaf.Subject.CommonName
	res.Issuer = leaf.Issuer.CommonName
	res.SANs = append([]string{}, leaf.DNSNames...)
	res.NotAfter = leaf.NotAfter
	res.DaysLeft = DaysUntil(leaf.NotAfter, time.Now())
	res.Status = Classify(leaf.NotAfter, time.Now(), opts.WarnDays, opts.CriticalDays)
	return res
}

// CheckMany checks every host concurrently with at most concurrency checks
// in flight. Results are returned in the same order as the input hosts.
func CheckMany(ctx context.Context, hosts []string, opts Options, concurrency int) []Result {
	if concurrency < 1 {
		concurrency = 1
	}
	results := make([]Result, len(hosts))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func(i int, h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = Check(ctx, h, opts)
		}(i, h)
	}
	wg.Wait()
	return results
}

// ParseHostsFile reads one host per line from path, skipping blank lines
// and lines starting with '#'.
func ParseHostsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var hosts []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hosts = append(hosts, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return hosts, nil
}
