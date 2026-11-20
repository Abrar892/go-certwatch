package certcheck

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDaysUntil(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		t    time.Time
		want int
	}{
		{"exactly ten days", now.Add(10 * 24 * time.Hour), 10},
		{"five days and 23 hours rounds down", now.Add(5*24*time.Hour + 23*time.Hour), 5},
		{"one hour left is zero days", now.Add(time.Hour), 0},
		{"expired one hour ago is minus one", now.Add(-time.Hour), -1},
		{"expired two days ago", now.Add(-48 * time.Hour), -2},
	}
	for _, tc := range cases {
		if got := DaysUntil(tc.t, now); got != tc.want {
			t.Errorf("%s: DaysUntil = %d, want %d", tc.name, got, tc.want)
		}
	}
}

func TestClassify(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name  string
		after time.Time
		want  Status
	}{
		{"far future is OK", now.Add(90 * 24 * time.Hour), StatusOK},
		{"just past warn window is OK", now.Add(31 * 24 * time.Hour), StatusOK},
		{"at warn threshold is warning", now.Add(30 * 24 * time.Hour), StatusWarning},
		{"inside warn window is warning", now.Add(10 * 24 * time.Hour), StatusWarning},
		{"at critical threshold is critical", now.Add(7 * 24 * time.Hour), StatusCritical},
		{"one day left is critical", now.Add(24 * time.Hour), StatusCritical},
		{"expired is expired", now.Add(-time.Hour), StatusExpired},
	}
	for _, tc := range cases {
		if got := Classify(tc.after, now, 30, 7); got != tc.want {
			t.Errorf("%s: Classify = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestStatusString(t *testing.T) {
	for _, s := range []Status{StatusOK, StatusWarning, StatusCritical, StatusExpired, StatusError} {
		if s.String() == "ERROR" && s != StatusError {
			t.Errorf("status %d rendered as ERROR", s)
		}
	}
	if StatusOK.String() != "OK" || StatusExpired.String() != "EXPIRED" {
		t.Errorf("unexpected status labels: %q %q", StatusOK, StatusExpired)
	}
}

func TestParseHost(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort string
		wantErr  bool
	}{
		{"example.com", "example.com", "443", false},
		{"example.com:8443", "example.com", "8443", false},
		{"https://example.com", "example.com", "443", false},
		{"https://example.com:8443/path?q=1", "example.com", "8443", false},
		{"http://example.com", "example.com", "443", false},
		{"example.com/path", "example.com", "443", false},
		{"[::1]:8443", "::1", "8443", false},
		{"  example.com  ", "example.com", "443", false},
		{"", "", "", true},
		{"   ", "", "", true},
		{":8443", "", "", true},
	}
	for _, tc := range cases {
		h, p, err := ParseHost(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseHost(%q): expected error, got %q:%q", tc.in, h, p)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseHost(%q): unexpected error: %v", tc.in, err)
			continue
		}
		if h != tc.wantHost || p != tc.wantPort {
			t.Errorf("ParseHost(%q) = %q:%q, want %q:%q", tc.in, h, p, tc.wantHost, tc.wantPort)
		}
	}
}

// testCert returns a self-signed TLS certificate expiring at notAfter.
func testCert(t *testing.T, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "certwatch-test"},
		Issuer:       pkix.Name{CommonName: "certwatch-test-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := tls.X509KeyPair(
		pemEncode("CERTIFICATE", der),
		pemEncode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)),
	)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}
	return cert
}

func pemEncode(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

// tlsServer starts an HTTPS server presenting a certificate that expires at
// notAfter, and returns its "host:port".
func tlsServer(t *testing.T, notAfter time.Time) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{testCert(t, notAfter)}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func TestCheckLiveServer(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name       string
		expiresIn  time.Duration
		wantStatus Status
	}{
		{"healthy cert is OK", 90 * 24 * time.Hour, StatusOK},
		{"expiring soon is warning", 10 * 24 * time.Hour, StatusWarning},
		{"expiring this week is critical", 3 * 24 * time.Hour, StatusCritical},
		{"expired cert is expired", -time.Hour, StatusExpired},
	}
	for _, tc := range cases {
		addr := tlsServer(t, now.Add(tc.expiresIn))
		res := Check(context.Background(), addr, DefaultOptions())
		if res.Status != tc.wantStatus {
			t.Errorf("%s: status = %v, want %v (days left %d, err %q)",
				tc.name, res.Status, tc.wantStatus, res.DaysLeft, res.Error)
		}
		if res.Subject != "certwatch-test" {
			t.Errorf("%s: subject = %q, want certwatch-test", tc.name, res.Subject)
		}
	}
}

func TestCheckUnreachable(t *testing.T) {
	// Port 1 on localhost refuses connections.
	res := Check(context.Background(), "127.0.0.1:1", Options{WarnDays: 30, CriticalDays: 7, Timeout: 2 * time.Second})
	if res.Status != StatusError {
		t.Errorf("unreachable host: status = %v, want ERROR", res.Status)
	}
	if res.Error == "" {
		t.Errorf("unreachable host: expected an error message")
	}
}

func TestCheckInvalidHost(t *testing.T) {
	res := Check(context.Background(), "", DefaultOptions())
	if res.Status != StatusError || res.Error == "" {
		t.Errorf("empty host: status = %v err %q, want ERROR with message", res.Status, res.Error)
	}
}

func TestCheckManyPreservesOrder(t *testing.T) {
	now := time.Now()
	healthy := tlsServer(t, now.Add(90*24*time.Hour))
	expiring := tlsServer(t, now.Add(2*24*time.Hour))
	hosts := []string{expiring, "127.0.0.1:1", healthy}
	results := CheckMany(context.Background(), hosts, DefaultOptions(), 2)
	if len(results) != len(hosts) {
		t.Fatalf("CheckMany returned %d results, want %d", len(results), len(hosts))
	}
	if results[0].Status != StatusCritical {
		t.Errorf("results[0] status = %v, want CRITICAL", results[0].Status)
	}
	if results[1].Status != StatusError {
		t.Errorf("results[1] status = %v, want ERROR", results[1].Status)
	}
	if results[2].Status != StatusOK {
		t.Errorf("results[2] status = %v, want OK", results[2].Status)
	}
	if results[0].Host != "127.0.0.1" || results[2].Host != "127.0.0.1" {
		t.Errorf("hosts not preserved in order: %q %q", results[0].Host, results[2].Host)
	}
}

func TestParseHostsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.txt")
	content := "# comment line\nexample.com\n\n  example.org:8443  \n# another comment\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write hosts file: %v", err)
	}
	hosts, err := ParseHostsFile(path)
	if err != nil {
		t.Fatalf("ParseHostsFile: %v", err)
	}
	want := []string{"example.com", "example.org:8443"}
	if len(hosts) != len(want) {
		t.Fatalf("ParseHostsFile = %v, want %v", hosts, want)
	}
	for i := range want {
		if hosts[i] != want[i] {
			t.Errorf("hosts[%d] = %q, want %q", i, hosts[i], want[i])
		}
	}
	if _, err := ParseHostsFile(filepath.Join(dir, "missing.txt")); err == nil {
		t.Errorf("ParseHostsFile on missing file: expected error")
	}
}
