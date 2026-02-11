# Bot Detector Research Project

Academic research project for classifying automated HTTP clients (bots, LLMs, crawlers) vs real browsers using transport-level fingerprinting.

## Project Goal

Create a single HTTP endpoint that classifies clients as `browser` or `bot` based exclusively on:
- TLS handshake patterns
- HTTP/2 negotiation behavior
- Header structure and semantics
- Request patterns

**No JavaScript challenges, no rate limiting** — pure network fingerprinting.

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
│   └── integration/     # Automated client tests
├── tools/
│   └── python/          # Analytics tools
├── logs/                # JSON traffic logs
└── docs/                # Research documentation
```

## Classification Signals

### TLS Level
- ALPN negotiation (h2, http/1.1)
- Cipher suite count and complexity
- TLS extensions count
- Connection behavior

### HTTP Level
- HTTP/2 vs HTTP/1.1
- Header order and structure
- Browser-specific headers (sec-fetch-*, accept-language)
- Header count and entropy

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

### Installation

```bash
# Clone repository
git clone https://github.com/muliwe/go-client-slassifier.git
cd go-client-slassifier

# Install dependencies and dev tools
go mod tidy
go install github.com/go-task/task/v3/cmd/task@latest
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

### Development

```bash
# Run server
task run

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

### Testing

```bash
# Run all tests
task test

# Run tests (short mode)
task test:short

# Test with curl
curl http://localhost:8080/

# Test health endpoint
curl http://localhost:8080/health
```

### Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Classify client as browser or bot |
| `GET /health` | Health check |

## Log Format

Each request is logged as JSON:

```json
{
  "timestamp": "2026-02-11T15:30:45Z",
  "request_id": "uuid",
  "classification": "bot",
  "confidence": 0.85,
  "fingerprint": {
    "tls": {...},
    "http": {...}
  },
  "signals": {...},
  "score": 4
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

## License

MIT (Academic Research)

## Authors

Research project for academic purposes.
