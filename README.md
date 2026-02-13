# Bot Detector Research Project

Academic research project for classifying automated HTTP clients (bots, LLMs, crawlers) vs real browsers using transport-level fingerprinting.

**Version**: 0.4.0 | [Changelog](CHANGELOG.md) | [Methodology](docs/METHODOLOGY.md)

### Performance Highlights

| Metric | Value |
|--------|-------|
| Throughput | **~14,500 RPS** (~870K RPM) |
| Avg Latency | **~1ms** (with TLS) |
| Classification Logic | **~7µs** per request |
| Concurrency | Tested up to 50 concurrent connections |

*Benchmark: localhost, HTTPS with full TLS fingerprinting (JA3/JA4/JA4H)*

## Project Goal

Create a single HTTP endpoint that classifies clients as `browser` or `bot` based exclusively on:
- TLS handshake patterns (JA3/JA4 fingerprinting)
- HTTP/2 negotiation behavior
- Header structure and semantics
- Request patterns

**No JavaScript challenges, no rate limiting** — pure network fingerprinting.

## Current Status

Phase 1 (TLS + HTTP Fingerprinting) complete:
- Full ClientHello capture with custom TLS listener
- JA3 and JA4 hash computation
- JA4H HTTP fingerprinting (method, version, cookies, headers, language)
- TLS and HTTP-based classification signals integrated into scoring
- Consistency checking between JA4H and HTTP signals (evasion detection)
- HTTPS server mode with configurable certificates

See [CHANGELOG.md](CHANGELOG.md) for detailed release notes.

## Architecture

```
client → TLS listener → fingerprint collector → classifier → response
```

### Tech Stack

- **Core**: Go (HTTP/2 server, TLS fingerprinting, classification)
- **Analytics**: Python (log analysis, pattern extraction, visualization)
- **Logging**: Structured JSON logs for research analysis

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
│   └── unit/            # Unit tests
├── tools/
│   ├── benchmark/       # HTTP benchmark tool
│   ├── python/          # Analytics tools
│   └── shell/           # Integration test scripts
├── logs/                # JSON traffic logs
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
- HTTP/2 vs HTTP/1.1
- JA4H fingerprinting (HTTP fingerprint from JA4+ family)
- Header order and structure
- Browser-specific headers (sec-fetch-*, accept-language)
- Header count and entropy
- JA4H consistency checking (cross-signal validation)

## Research Workflow

1. **Collect**: Run server, generate traffic (curl, browsers, LLM tools)
2. **Log**: All requests logged as structured JSON
3. **Analyze**: Python tools extract patterns from logs
4. **Iterate**: Update classification heuristics based on findings
5. **Test**: Automated integration tests validate behavior

## Getting Started

### Prerequisites

- Go 1.26+
- `$GOPATH/bin` in PATH
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

Each request is logged as JSON with full fingerprint data:

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

## License

MIT (Academic Research)

## Authors

Research project for academic purposes.
