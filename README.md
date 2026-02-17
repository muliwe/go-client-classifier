# Bot Detector Research Project

Academic research project for classifying automated HTTP clients (bots, LLMs, crawlers) vs real browsers using transport-level fingerprinting.

**Version**: 0.6.0 | [Changelog](CHANGELOG.md) | [Methodology](docs/METHODOLOGY.md)

### Performance Highlights

Benchmarks: localhost, 30s, 50 concurrent connections; Go server only (no nginx in front).

| Mode | RPS | RPM | Latency avg |
|------|-----|-----|--------------|
| HTTP (no TLS) | **~11,550** | ~693K | ~4.3 ms |
| HTTPS (TLS fingerprinting, JA3/JA4/JA4H) | **~8,210** | ~493K | ~6.1 ms |

Classification logic: **~7µs** per request. Benchmarks with nginx (TLS termination + X-FP-* at edge) will be added later.

## Project Goal

Create a single HTTP endpoint that classifies clients as `browser` or `bot` based exclusively on:
- TLS handshake patterns (JA3/JA4 fingerprinting)
- HTTP/2 negotiation behavior
- Header structure and semantics
- Request patterns

**No JavaScript challenges, no rate limiting** — pure network fingerprinting.

## Current Status

Phase 1 (TLS + HTTP Fingerprinting) and Phase 2/3 (HTTP/2 + cross-validation) in place:
- Full ClientHello capture with custom TLS listener; JA3 and JA4 hash computation
- JA4H HTTP fingerprinting (method, version, cookies, headers, language)
- TLS and HTTP-based classification signals integrated into scoring
- Consistency checking between JA4H and HTTP signals (evasion detection)
- HTTPS server mode with configurable certificates

**Planned**: HTTP/2 frame-level statistics (SETTINGS, WINDOW_UPDATE, PRIORITY) will be collected via **nginx modules** in front of the Go backend, rather than implementing low-level H2 parsing in Go — mature HTTP/2 fingerprinting libraries for Go are not available, while nginx with add-on modules (e.g. [nginx-http2-fingerprint](https://github.com/Xetera/nginx-http2-fingerprint)) provides proven passive fingerprinting at the edge. See [docs/nginx.md](docs/nginx.md) and [Methodology → Phase 2](docs/METHODOLOGY.md#phase-2-http2-deep-inspection) for rationale and references.

See [CHANGELOG.md](CHANGELOG.md) for detailed release notes.

## Architecture

**Direct TLS (Go terminates HTTPS):**
```
client → TLS listener (Go) → fingerprint collector → classifier → response
```

**Via nginx (TLS termination at edge, fingerprint via headers):**
```
client → nginx (TLS + JA3 + H2 fingerprint) → proxy_pass → Go (HTTP :8080, X-FP-* headers) → collector → classifier → response
```
See [docs/nginx.md](docs/nginx.md) and Methodology Appendix F.

### Tech Stack

- **Core**: Go (HTTP/2 server, TLS fingerprinting, classification)
- **Analytics**: Python (log analysis, pattern extraction, visualization)
- **Logging**: Structured JSON logs per day (`logs/requests_YYYYMMDD.jsonl`) for research analysis

## Project Structure

```
.
├── cmd/
│   └── server/          # HTTP server entry point
├── internal/
│   ├── fingerprint/     # TLS/HTTP signal collection
│   ├── classifier/      # Rule-based classification
│   ├── logger/          # Structured JSON logging
│   └── server/          # HTTP handlers
├── tests/
│   ├── integration/     # Automated client tests
│   ├── unit/            # Unit tests
│   └── testdata/        # Test stubs (e.g. ja4db_fixture.json for tests)
├── tools/
│   ├── benchmark/       # HTTP benchmark tool
│   ├── python/          # Analytics tools
│   └── shell/           # Integration test scripts
├── internal/fingerprint/data/  # JA4 DB path (ja4db.json downloaded on first start if missing)
├── logs/                # JSON traffic logs (requests_YYYYMMDD.jsonl per day)
└── docs/                # Research documentation
```

## Classification Signals

### TLS Level
- Full ClientHello capture via custom TLS listener
- JA3/JA4 fingerprint hashing
- ALPN negotiation (h2, http/1.1)
- Cipher suite count and complexity (15+ suggests browser)
- TLS extensions count (10+ suggests browser)
- Supported versions, signature schemes, elliptic curve groups
- Session ticket and early data support

### HTTP Level
- HTTP/2 vs HTTP/1.1; HTTP/2 fingerprint (SETTINGS, PRIORITY, window) when provided by proxy
- JA4H fingerprinting (HTTP fingerprint from JA4+ family)
- Header order and structure; browser-specific headers (sec-fetch-*, accept-language); header count and entropy
- **Cross-signal consistency**: JA4H vs HTTP; TLS vs User-Agent (known library/browser JA3/JA4); H2 vs JA4 (ALPN); TLS ALPN vs HTTP version (direct TLS)

## Research Workflow

1. **Collect**: Run server, generate traffic (curl, browsers, LLM tools)
2. **Log**: All requests logged as structured JSON to daily files (`logs/requests_YYYYMMDD.jsonl`)
3. **Analyze**: Python tools extract patterns from logs
4. **Iterate**: Update classification heuristics based on findings
5. **Test**: Automated integration tests validate behavior

## Getting Started

### Prerequisites

- **Go 1.22+** — [Download](https://go.dev/dl/) installers for Windows, macOS, Linux; or install via package manager (e.g. `winget install GoLang.Go`, `brew install go`, `apt install golang-go`). Ensure `go` is on your PATH.
- Go tools directory in PATH — add `$HOME/go/bin` (default when Go is installed in the usual way). Required so `task` and `golangci-lint` are found after `go install`. Using this explicit path avoids errors when `go` cannot read the current directory (e.g. after `sudo su`). Do not install the `task` or `taskwarrior` apt/snap packages (they are different programs).
- TLS certificate and key (for HTTPS mode)

### Installation

```bash
# Clone repository
git clone https://github.com/muliwe/go-client-classifier.git
cd go-client-classifier

# Install dependencies and dev tools
go mod tidy
go install github.com/go-task/task/v3/cmd/task@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Ensure Go bin is on PATH (required for `task` and `golangci-lint`)
# Use explicit path so it works even when current directory has permission issues (e.g. after sudo su)
export PATH=$PATH:$HOME/go/bin

# To make it permanent, add the same line to your shell profile and reload:
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc && source ~/.bashrc   # bash
```

### TLS Certificate Setup

For TLS fingerprinting to work, the server must run in HTTPS mode. Place your certificate and key in the `certs/` directory:

```
certs/
├── server.crt
└── server.key
```

**Note**: The `certs/` directory is in `.gitignore` — certificates are not committed to the repository.

To generate a self-signed certificate for local development:

```bash
# Create certs directory
mkdir certs

# Generate self-signed certificate (valid for 1 year)
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt \
  -days 365 -nodes -subj "/CN=localhost"
```

Add the certificate to your system's trusted certificates for browser testing without warnings.

**Using Let's Encrypt (certbot)** — for a public hostname with HTTPS:

```bash
# Install certbot (Ubuntu/Debian)
sudo apt install certbot

# Obtain a certificate (standalone mode: port 80 must be free for the challenge)
sudo certbot certonly --standalone -d your-domain.example.com

# Certbot stores certs under /etc/letsencrypt/live/<domain>/
# Point the server at them via env or symlink into certs/:
#   TLS_CERT=/etc/letsencrypt/live/your-domain.example.com/fullchain.pem
#   TLS_KEY=/etc/letsencrypt/live/your-domain.example.com/privkey.pem
# Or copy/symlink into project certs/ (ensure deploy user can read; certbot files are root-readable):
sudo cp /etc/letsencrypt/live/your-domain.example.com/fullchain.pem certs/server.crt
sudo cp /etc/letsencrypt/live/your-domain.example.com/privkey.pem certs/server.key
sudo chown $(whoami) certs/server.crt certs/server.key
```

Renewal: certbot can renew via `sudo certbot renew` (e.g. from cron or systemd timer). After renewal, restart the Go server so it reloads the certs.

### Development

```bash
# Build binary
task build

# Run server (HTTP mode, no TLS fingerprinting)
task run

# Run server with HTTPS (required for TLS fingerprinting)
task run:tls

# Run tests
task test

# Run linter
task lint

# Format code
task fmt

# Run all checks (fmt, lint, test)
task check

# List all available tasks
task --list
```

### Build

```bash
# Build binary to bin/server
task build

# Or manually
go build -o bin/server ./cmd/server

# Run the binary
./bin/server
```

### Optional: JA4 dictionary (deploy)

The server uses a JA4 fingerprint database (ja4db.com) for TLS vs User-Agent consistency. **If the file is absent, the server downloads it itself** on first use (saved to `internal/fingerprint/data/ja4db.json` when running from repo root). No manual step is required for basic runs.

For **deployment**, you can optionally download the dictionary manually (e.g. to avoid first-request latency or when the host has no outbound HTTPS):

```bash
# From repo root; creates internal/fingerprint/data/ja4db.json
curl -o internal/fingerprint/data/ja4db.json "https://ja4db.com/api/read/"
```

Or with PowerShell:

```powershell
Invoke-WebRequest -Uri "https://ja4db.com/api/read/" -OutFile "internal/fingerprint/data/ja4db.json" -UseBasicParsing
```

Ensure the directory exists (`mkdir -p internal/fingerprint/data` or `New-Item -ItemType Directory -Force -Path internal/fingerprint/data`). Override path with env **`JA4DB_PATH`** if you place the file elsewhere.

### Testing

```bash
# Run all tests
task test

# Run tests (short mode)
task test:short

# Test with curl (HTTP mode)
curl http://localhost:8080/

# Test with curl (HTTPS mode)
curl https://localhost:8443/

# Test health endpoint
curl http://localhost:8080/health
curl https://localhost:8443/health
```

### Integration Tests

Run integration tests against a running server using curl:

```bash
# HTTP mode
task run                    # Start server (terminal 1)
task integration            # Run tests (terminal 2)

# HTTPS mode (TLS fingerprinting)
task run:tls                # Start HTTPS server (terminal 1)
task integration:tls        # Run tests with --insecure (terminal 2)

# Custom base URL
task integration BASE_URL=http://localhost:3000
task integration:tls BASE_URL=https://localhost:8443
```

### Benchmark

Run HTTP performance benchmark against a running server:

```bash
# Start server
task run:tls                # HTTPS mode (terminal 1)

# Run benchmark (terminal 2)
task bench:tls              # Default: 10s, 10 concurrent connections

# Custom parameters
task bench:tls DURATION=30s CONCURRENCY=50

# HTTP mode
task bench URL=http://localhost:8080/ DURATION=10s CONCURRENCY=10
```

Benchmark output includes RPS, RPM, and latency statistics (avg/min/max).

The integration tests automatically detect the OS and use:
- `tools/shell/integration_test.ps1` for Windows (PowerShell)
- `tools/shell/integration_test.sh` for Unix (Linux/macOS)

Tests verify:
- `GET /health` — health check endpoint returns `{"status":"ok"}`
- `GET /` — classify endpoint returns classification
- `GET /debug` — debug endpoint returns fingerprint data
- curl is correctly detected as bot

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Classify client as browser or bot |
| `GET /health` | Health check |
| `GET /debug` | Debug info with full fingerprint (dev only) |

## Log Format

Each request is logged as one JSON line (JSONL) with full fingerprint data. Log files are written by day in UTC: `logs/requests_YYYYMMDD.jsonl` (e.g. `logs/requests_20260217.jsonl`). The server rotates to a new file automatically when the date changes.

```json
{
  "timestamp": "2026-02-12T12:40:35Z",
  "request_id": "uuid",
  "classification": "browser",
  "confidence": 0.99,
  "fingerprint": {
    "tls": {
      "version": "TLS 1.3",
      "cipher_suites_count": 16,
      "extensions_count": 18,
      "ja3_hash": "9b0d79d10808bc0e509b4789f870a650",
      "ja4_hash": "t13d1516h2_8daaf6152771_d8a2da3f94cd",
      "supported_groups": ["GREASE", "x25519", "secp256r1", "secp384r1"]
    },
    "http": {
      "version": "HTTP/2.0",
      "header_count": 14
    }
  },
  "signals": {
    "browser_score": 18,
    "bot_score": 0,
    "score_breakdown": "BROWSER[http2(+2) sec-fetch(+3) ...] BOT[]"
  },
  "score": 18
}
```

### Production deploy

You can run the service on Ubuntu as a systemd unit: one process listens on both HTTP and HTTPS, and restarts on failure or after a reboot.

**1. Build the Linux binary**

On your dev machine or in CI:

```bash
task build:prod
```

The binary will be at `bin/server`. Copy it to the server (e.g. `/opt/go-client-classifier/`).

**2. Certificates**

Place the certificate and key in the app directory, for example:

```
/opt/go-client-classifier/
├── server          # binary
├── certs/
│   ├── server.crt
│   └── server.key
└── logs/           # created automatically
```

**3. systemd unit file**

Create `/etc/systemd/system/go-client-classifier.service`:

```ini
[Unit]
Description=Go Client Classifier (bot detector)
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/go-client-classifier
ExecStart=/opt/go-client-classifier/server
Restart=always
RestartSec=5

# HTTP :8080, HTTPS :8443
Environment=PORT=8080
Environment=TLS_PORT=8443
Environment=TLS_CERT=/opt/go-client-classifier/certs/server.crt
Environment=TLS_KEY=/opt/go-client-classifier/certs/server.key

# Optional: disable request logging, only health/debug
# Environment=DEBUG=false

[Install]
WantedBy=multi-user.target
```

Alternatively, put variables in a file: create `/opt/go-client-classifier/.env` (or `environment.conf`) and add `EnvironmentFile=/opt/go-client-classifier/.env` to the unit.

**4. Enable and start**

```bash
sudo systemctl daemon-reload
sudo systemctl enable go-client-classifier
sudo systemctl start go-client-classifier
sudo systemctl status go-client-classifier
```

Verify: `curl http://localhost:8080/health` and `curl -k https://localhost:8443/health`.

**Environment variables**

| Variable    | Description                              | Example             |
|------------|------------------------------------------|---------------------|
| `PORT`     | HTTP port                                | `8080`              |
| `TLS_PORT` | HTTPS port (when using TLS)              | `8443`              |
| `TLS_CERT` | Path to certificate file                 | `certs/server.crt`  |
| `TLS_KEY`  | Path to key file                         | `certs/server.key`  |
| `DEBUG`    | Enable `/debug` endpoint                  | `true` / `false`    |

If only `TLS_CERT` and `TLS_KEY` are set (no `TLS_PORT`), the service runs in HTTPS-only mode on `PORT`.

## Research Questions

1. Can transport-level signals reliably distinguish browsers from automation?
2. Which signals are most predictive?
3. How do sophisticated bots (headless Chrome) behave?
4. What are the false positive/negative rates?

## Pre-commit Hooks

Project uses git pre-commit hooks for code quality:
- Format check (`go fmt`)
- Linter (`golangci-lint`)
- Tests (`go test`)

Hooks are automatically run before each commit.

## Documentation

- [CHANGELOG.md](CHANGELOG.md) — version history and release notes
- [docs/METHODOLOGY.md](docs/METHODOLOGY.md) — research methodology, signals, scoring algorithm, references
- [docs/nginx.md](docs/nginx.md) — nginx setup for TLS termination, HTTP/2 fingerprint (X-FP-H2), JA3 (X-FP-JA3); Go consumes headers and uses H2/JA3 in cross-validation (Appendix G)

## License

MIT (Academic Research)

## Authors

Research project for academic purposes.
