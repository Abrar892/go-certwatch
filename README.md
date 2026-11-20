# certwatch

A small CLI that checks the TLS certificates of one or more hosts and reports
how many days each certificate has left before it expires. Built for the
weekly "which of our domains is about to expire?" check that every team
forgets until a certificate actually lapses.

```text
$ certwatch example.com example.org:8443
HOST                EXPIRES     DAYS LEFT  ISSUER              STATUS
example.com         2027-02-14  86         R13                 OK
example.org:8443    2026-11-27  7          R13                 CRITICAL

1 ok, 1 critical
```

## Why this exists

Certificate expiry is a silent outage: nothing alerts you, and the first
symptom is users seeing a browser warning. `certwatch` gives you a
zero-dependency binary you can drop into a cron job or a CI step and get a
clear pass/fail answer.

## Design decisions

- **Expiry reporting, not trust validation.** The check intentionally
  accepts any certificate chain (`InsecureSkipVerify`). A self-signed or
  already-expired certificate is still reported with its real expiry date
  instead of failing the handshake — the expiry date is the information
  you need.
- **Concurrent checks with a bounded worker pool.** Hosts are checked in
  parallel (default 10 in flight) but results are returned in input order,
  so output is stable and diffable between runs.
- **Whole-day granularity, rounded down.** A certificate expiring in 5 days
  and 23 hours reports 5 days left, so a threshold is never crossed
  silently between two runs a few hours apart.
- **Machine-readable output.** `-json` emits the full result set for
  scripting, and the exit code (0 = all OK, 1 = warning/critical/expired/
  unreachable, 2 = usage error) makes it usable as a CI gate.

## Install

Requires Go 1.22 or newer.

```sh
go build -o certwatch ./cmd/certwatch
```

## Usage

```sh
# Check a single host (port defaults to 443)
certwatch example.com

# Check several hosts, custom thresholds
certwatch -warn-days 45 -critical-days 14 example.com example.org api.example.net:8443

# Check hosts listed one per line in a file
certwatch -file hosts.txt

# JSON output for scripting or CI
certwatch -json example.com

# Accept a URL-style host as well
certwatch https://example.com
```

## Flags

| Flag | Default | Description |
| --- | --- | --- |
| `-warn-days` | 30 | Expiry within this many days is a warning |
| `-critical-days` | 7 | Expiry within this many days is critical |
| `-timeout` | 10s | Per-host dial timeout |
| `-concurrency` | 10 | Maximum concurrent checks |
| `-file` | — | File with one host per line (`#` comments allowed) |
| `-json` | false | Print results as JSON |
| `-version` | false | Print version and exit |

## Tests

```sh
go test ./...
```

Tests cover threshold classification, host parsing, hosts-file parsing,
and live checks against local HTTPS servers presenting certificates with
known expiry dates (healthy, warning, critical, expired).

## Proxies

`certwatch` dials hosts directly. In environments where outbound traffic
must go through an HTTP proxy, direct dials will fail and the host is
reported as `ERROR` with the handshake error — run it from a host with
direct egress, or put the check behind your proxy's allow-list.

## License

MIT — see [LICENSE](LICENSE).
