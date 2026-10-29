# Rasadbin SIEM Platform

**Rasadbin** is a Linux-first Security Information and Event Management (SIEM) platform written in Go, designed to collect, normalize, analyze, and correlate security events from network traffic, operating system logs, and service logs through a unified web interface.

The project aims to provide a lightweight, extensible, and self-hosted security monitoring solution with a modular architecture and a clear path toward advanced threat detection.

> **Project status:** Early development. Core infrastructure is under construction. Network capture, log collection, detection rules, persistent event storage, and the web interface are planned components and should not be considered production-ready until implemented and tested.

## Features and Roadmap

### Data Collection
- [ ] Live network packet capture on Linux network interfaces.
- [ ] TCP and UDP flow metadata extraction.
- [ ] Offline PCAP processing for testing and investigation.
- [ ] System log collection through `systemd-journald`.
- [ ] File-based log collection with rotation handling.
- [ ] Linux authentication and privilege-escalation event monitoring.
- [ ] Service-specific log parsers for Nginx, SSH, Docker, and other applications.
- [ ] Configurable collection sources and filters.

### Event Processing
- [ ] Common event schema for all collection sources.
- [ ] Event normalization and validation.
- [ ] Host, process, user, and network context enrichment.
- [ ] Duplicate event detection.
- [ ] Bounded ingestion queues and backpressure handling.
- [ ] Persistent checkpoints for reliable log collection.
- [ ] Event correlation across multiple data sources.

### Detection and Alerting
- [ ] Configurable detection rules using YAML or JSON.
- [ ] Time-window-based event aggregation.
- [ ] Threshold-based detection.
- [ ] SSH brute-force detection.
- [ ] Network port-scan detection.
- [ ] Suspicious authentication and privilege-escalation detection.
- [ ] Service failure monitoring.
- [ ] Alert deduplication, severity, and investigation status.
- [ ] Incident and case management.
- [ ] Future support for a compatible subset of Sigma rules.

### Web Interface and API
- [ ] Security overview dashboard.
- [ ] Searchable event explorer.
- [ ] Alert and incident management.
- [ ] Network flow explorer.
- [ ] Collector health monitoring.
- [ ] Detection rule management.
- [ ] REST API with versioned endpoints.
- [ ] Server-Sent Events (SSE) for live updates.
- [ ] Authentication, authorization, and administrative audit logging.

### Operations
- [ ] Linux service integration using systemd.
- [ ] Configuration validation and diagnostics.
- [ ] Health and readiness endpoints.
- [ ] Metrics and performance monitoring.
- [ ] Configurable event retention.
- [ ] Graceful shutdown and resource cleanup.
- [ ] Automated unit, integration, and load tests.

## Architecture

Rasadbin follows a modular monolithic architecture. Collection, processing, detection, storage, and API components are designed to remain independent so they can evolve without requiring a complete rewrite.

```text
+------------------------------------------------------+
|                    Web Interface                     |
|         Dashboard | Events | Alerts | Rules          |
+----------------------------+-------------------------+
                             |
+----------------------------v-------------------------+
|                    REST API / SSE                    |
|          Authentication | Authorization              |
+----------------------------+-------------------------+
                             |
+----------------------------v-------------------------+
|                   Event Processing                   |
| Normalize | Enrich | Deduplicate | Correlate         |
+----------------------------+-------------------------+
                             |
+----------------------------v-------------------------+
|                    Detection Engine                  |
|         Rules | Thresholds | Time Windows            |
+----------------------------+-------------------------+
                             |
+----------------------------v-------------------------+
|                     Storage Layer                    |
|       Events | Alerts | Rules | Checkpoints           |
+------------------------------------------------------+

                       Data Sources

+------------------+ +----------------+ +---------------+
| Network Capture  | | System Logs    | | Service Logs  |
| PCAP / TCP / UDP | | journald/Audit | | Files / Syslog|
+------------------+ +----------------+ +---------------+
```

### Core Components

| Component | Responsibility |
|---|---|
| Network Collector | Captures packets and extracts network metadata. |
| System Collector | Reads operating system and authentication events. |
| Service Log Collector | Reads and parses application and service logs. |
| Event Pipeline | Normalizes, enriches, and routes events. |
| Detection Engine | Evaluates rules and identifies suspicious behavior. |
| Alert Manager | Creates, deduplicates, and tracks security alerts. |
| Storage Layer | Persists events, configuration, rules, and investigation data. |
| REST API | Exposes event search, management, and monitoring endpoints. |
| Web Interface | Provides centralized security visibility and investigation tools. |

## Technology Stack

| Area | Technology |
|---|---|
| Backend | Go |
| HTTP API | Go `net/http`, with `chi` as an optional router |
| Network Capture | `gopacket`, libpcap, and potentially Linux AF_PACKET |
| System Logs | systemd journal APIs and Linux logging facilities |
| Initial Storage | SQLite |
| Full-Text Search | SQLite FTS5 |
| Frontend | React, TypeScript, and Vite |
| Live Updates | Server-Sent Events (SSE) |
| Configuration | YAML or environment-based configuration |
| Service Management | systemd |
| Testing | Go testing, integration tests, and traffic replay |

The storage layer is intended to be replaceable. PostgreSQL or ClickHouse may be considered later if workload measurements show that the initial SQLite implementation is insufficient.

## Requirements

### Development Environment

- Linux development environment.
- Go toolchain compatible with the version declared in `go.mod`.
- Git.
- A C compiler and CGO toolchain if using `github.com/mattn/go-sqlite3`.
- Node.js and npm for frontend development.
- `libpcap` development libraries for packet capture.
- Root privileges or appropriate Linux capabilities for selected packet-capture operations.

On Debian or Ubuntu:

```bash
sudo apt update

sudo apt install -y \
  git \
  build-essential \
  pkg-config \
  libpcap-dev
```

Install Go and Node.js separately if they are not already available.

## Getting Started

### 1. Clone the Repository

```bash
git clone <REPOSITORY_URL> rasadbin
cd rasadbin
```

Replace `<REPOSITORY_URL>` with the actual repository URL.

### 2. Initialize the Go Module

If the repository does not already contain a `go.mod` file:

```bash
go mod init github.com/<YOUR_USERNAME>/rasadbin
```

If `go.mod` already exists, do not initialize it again.

### 3. Install Go Dependencies

Install only the dependencies required by the components currently being developed:

```bash
go get github.com/go-chi/chi/v5
go get github.com/mattn/go-sqlite3
go get github.com/google/gopacket
go get github.com/coreos/go-systemd/v22

go mod tidy
```

Some dependencies may not yet be used by the current implementation. Keep `go.mod` synchronized as the codebase evolves.

### 4. Run the Application

From the repository root:

```bash
go run ./cmd/sentinel help
go run ./cmd/sentinel version
go run ./cmd/sentinel run
```

The initial CLI executable is named `sentinel`. The product and repository are named Rasadbin; the executable can be renamed to `rasadbin` as part of a later packaging decision.

By default, the HTTP server listens on:

```text
127.0.0.1:8080
```

### 5. Verify the Health Endpoint

In another terminal:

```bash
curl -i http://127.0.0.1:8080/healthz
```

The initial implementation should return an HTTP 200 response similar to:

```json
{
  "status": "ok",
  "service": "sentinel",
  "version": "0.1.0"
}
```

This endpoint currently checks basic HTTP service availability. It does not yet guarantee that collectors, storage, or detection components are operational.

### 6. Build the Binary

```bash
mkdir -p bin

go build \
  -ldflags "-X main.version=0.1.0" \
  -o bin/sentinel \
  ./cmd/sentinel
```

Run the compiled binary:

```bash
./bin/sentinel version
./bin/sentinel run
```

## Development Commands

Run the following commands from the repository root.

```bash
# Format Go source files
gofmt -w .

# Run all Go tests
go test ./...

# Run the race detector
go test -race ./...

# Run static analysis
go vet ./...

# Build the application
go build -o bin/sentinel ./cmd/sentinel
```

Use `golangci-lint` when configured for the repository.

## Configuration

The configuration system is planned to support a YAML file, environment variables, and command-line overrides.

A future configuration file may look like this:

```yaml
server:
  listen: "127.0.0.1:8080"
  read_timeout: 15s
  write_timeout: 30s

storage:
  driver: sqlite
  path: "./data/rasadbin.db"

logging:
  level: info
  format: json

collectors:
  network:
    enabled: false
    interfaces: []
    capture_mode: metadata

  journald:
    enabled: false

  filelog:
    enabled: false
    paths: []

detection:
  enabled: false
  rules_path: "./configs/rules"

retention:
  enabled: false
  days: 30
```

**Note:** This is an illustrative configuration schema, not a guarantee that these options are currently supported. Collector activation, storage initialization, retention, and configuration loading must be implemented before these settings take effect.

Never store credentials or other secrets in a committed configuration file.

## Detection Rules

Detection rules will describe the events to match, the conditions to evaluate, and the resulting alert.

Example planned rule:

```yaml
id: linux.ssh.bruteforce
name: Repeated SSH authentication failures
enabled: true

source:
  category: authentication
  event_type: login_failed
  service: sshd

match:
  group_by:
    - host.name
    - source.ip
  threshold: 8
  window: 2m

severity: high

alert:
  title: Possible SSH brute-force attempt
```

This example defines the intended rule format. The rule engine, event field mappings, validation, aggregation, and alert generation must be implemented before the rule can execute.

## Security Considerations

Rasadbin is intended to handle sensitive system and network telemetry. Security must be considered throughout development.

- Bind the management interface to localhost by default.
- Do not expose the API publicly without appropriate authentication, authorization, and TLS.
- Avoid running the entire application as root.
- Grant packet-capture and log-reading permissions only where required.
- Validate and sanitize untrusted event data.
- Protect management endpoints against unauthorized changes.
- Record sensitive administrative operations in an audit log.
- Apply retention limits and protect stored event data.
- Avoid collecting or retaining packet payloads unless explicitly required.
- Do not treat a successful health check as proof that the entire SIEM is functioning correctly.

Packet visibility depends on the network interface and deployment topology. Capturing on an ordinary interface does not automatically expose traffic between other hosts. A network TAP, mirrored switch port, or suitable observation point may be required.

## Project Structure

```text
rasadbin/
├── cmd/
│   └── sentinel/
│       └── main.go
├── internal/
│   ├── app/
│   ├── config/
│   ├── event/
│   ├── collector/
│   │   ├── network/
│   │   ├── journald/
│   │   └── filelog/
│   ├── pipeline/
│   ├── detection/
│   ├── storage/
│   │   └── sqlite/
│   ├── alert/
│   ├── search/
│   ├── api/
│   │   └── handlers/
│   └── security/
├── configs/
│   └── rules/
├── deploy/
├── migrations/
├── tests/
│   ├── fixtures/
│   └── integration/
├── web/
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

The structure is a target layout. Some directories and components may not exist in the current repository yet.

## Design Principles

1. **Modularity:** Collectors, processing, detection, storage, and API components should have clear boundaries.
2. **Linux-first:** Prioritize Linux collection mechanisms and deployment in the initial release.
3. **Extensibility:** New data sources and detection rules should not require rewriting the event-processing pipeline.
4. **Resource control:** Use bounded queues, explicit timeouts, and backpressure handling.
5. **Reliability:** Track collection checkpoints and handle restarts, log rotation, and partial failures.
6. **Observability:** Monitor collector health, processing latency, dropped events, and storage failures.
7. **Security by default:** Apply least privilege, validate inputs, and keep the management interface protected.
8. **Testability:** Support synthetic events and offline PCAP replay for reproducible tests.

## Contributing

Contributions are welcome as the project develops.

When submitting changes:

- Follow standard Go formatting conventions.
- Keep packages focused on a single responsibility.
- Add unit tests for new functionality.
- Include integration tests for collectors and storage changes where practical.
- Document new configuration options and detection rules.
- Avoid introducing unnecessary dependencies.
- Report security vulnerabilities privately rather than publishing exploit details in public issues.

Contribution guidelines and the security reporting process will be documented separately as the project matures.

## License

The project license has not yet been specified.

Add a `LICENSE` file before publishing a release or distributing the software. Do not assume that the project is open source under a particular license until one has been selected.

## Disclaimer

Rasadbin is an early-stage security monitoring project. It is not yet a replacement for a mature production SIEM, endpoint detection platform, or network intrusion detection system.

Use it initially in a controlled development or test environment. Validate detection coverage, event loss, access controls, and recovery behavior before relying on it for security-critical monitoring.
