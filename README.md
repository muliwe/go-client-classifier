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
- Python 3.12+
- Git

### Installation

```bash
# Initialize Go module
go mod init github.com/muliwe/go-client-slassifier

# Install dependencies
go mod tidy

# Run server
go run cmd/server/main.go
```

### Testing

```bash
# Run integration tests
go test ./tests/integration/...

# Test with curl
curl http://localhost:8080/

# Test with browser
# Open http://localhost:8080/ in your browser
```

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

## License

MIT (Academic Research)

## Authors

Research project for academic purposes.
