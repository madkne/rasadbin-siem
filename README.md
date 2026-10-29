# Rasadbin SIEM Platform

**Rasadbin** is a Linux-first Security Information and Event Management (SIEM) platform written in Go, designed to collect, normalize, analyze, and correlate security events from network traffic, operating system logs, and service logs through a unified web interface.

The project aims to provide a lightweight, extensible, and self-hosted security monitoring solution with a modular architecture and a clear path toward advanced threat detection.

> **Project status:** Early development. The web UI, authentication, settings persistence, integration registry, and Linux AF_PACKET network collector are implemented. Log collection, detection rules, persistent event storage, and alerting are planned components and should not be considered production-ready until implemented and tested.

## Features and Roadmap

### Data Collection

- [x] Live network packet capture on Linux network interfaces (AF_PACKET, metadata only).
- [x] TCP and UDP flow metadata extraction.
- [ ] Offline PCAP processing for testing and investigation.
- [ ] System log collection through `systemd-journald`.
- [x] File-based syslog collection with rotation and truncation handling.
- [x] Linux authentication and privilege-escalation event parsing (syslog heuristic severity).
- [ ] Service-specific log parsers for Nginx, SSH, Docker, and other applications.
- [ ] Configurable collection sources and filters.

### Event Processing

- [x] Common event schema for all collection sources (`web.Event`).
- [x] Event normalization and validation.
- [ ] Host, process, user, and network context enrichment.
- [ ] Duplicate event detection.
- [x] Bounded ingestion queues (hub recent buffer, store channel with drop counter).
- [ ] Persistent checkpoints for reliable log collection.
- [ ] Event correlation across multiple data sources.

### Detection and Alerting

- [x] Configurable detection rules using YAML or JSON (`data/rules/`).
- [ ] Time-window-based event aggregation.
- [ ] Threshold-based detection.
- [x] SSH brute-force detection.
- [x] Network port-scan detection.
- [x] Repeated authentication-failure detection.
- [ ] Service failure monitoring.
- [x] In-memory alert generation, deduplication, severity, and open status.
- [ ] Incident and case management.
- [ ] Future support for a compatible subset of Sigma rules.

### Web Interface and API

- [x] Security overview dashboard with live stats and event feed (WebSocket).
- [x] Searchable event explorer (Discover page with time range, severity, source filters, histogram and live updates).
- [ ] Alert and incident management.
- [ ] Network flow explorer.
- [x] Collector health monitoring (integration status in the UI).
- [ ] Detection rule management.
- [ ] REST API with versioned endpoints (currently WebSocket-only).
- [x] Live updates over WebSocket (not SSE).
- [x] Authentication, authorization, and administrative audit logging (in-memory users).
- [x] Admin settings page (instance name, log level, session timeout, retention, refresh interval).
- [x] Built-in integration control plane with enable/disable and alerting toggles.
- [x] Discover-style log explorer with time range, severity, source filters and a histogram.

### Operations

- [ ] Linux service integration using systemd.
- [ ] Configuration validation and diagnostics.
- [x] Health endpoint (`/healthz`).
- [ ] Metrics and performance monitoring.
- [ ] Configurable event retention (setting persisted, not yet enforced).
- [x] Graceful shutdown and resource cleanup.
- [x] Persistent event storage via GORM (SQLite, PostgreSQL, MySQL).
- [ ] Automated unit, integration, and load tests (partial: network decoding and integration store tests exist).

## Architecture

Rasadbin follows a modular monolithic architecture. Collection, processing, detection, storage, and API components are designed to remain independent so they can evolve without requiring a complete rewrite.

```text
+------------------------------------------------------+
|                    Web Interface                     |
|    Dashboard | Integrations | Settings | Events      |
+----------------------------+-------------------------+
                             |
+----------------------------v-------------------------+
|                WebSocket Hub / Auth                  |
|     Sessions | Integrations | Settings | Events      |
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
| AF_PACKET / TCP  | | journald/Audit | | Files / Syslog|
+------------------+ +----------------+ +---------------+
```

### Core Components

| Component             | Responsibility                                                           |
| --------------------- | ------------------------------------------------------------------------ |
| Network Collector     | Captures packets via AF_PACKET and extracts L3/L4 metadata.              |
| System Collector      | Reads operating system and authentication events (planned).              |
| Service Log Collector | Reads and parses application and service logs (planned).                 |
| Event Pipeline        | Normalizes, enriches, and routes events (seam in place).                 |
| Detection Engine      | Evaluates rules and identifies suspicious behavior (planned).            |
| Alert Manager         | Creates, deduplicates, and tracks security alerts (planned).             |
| Storage Layer         | Persists events, configuration, rules, and investigation data (planned). |
| WebSocket API         | Exposes live dashboard, integration control, and settings.               |
| Web Interface         | Provides centralized security visibility and investigation tools.        |

## Technology Stack

| Area               | Technology                                                  |
| ------------------ | ----------------------------------------------------------- |
| Backend            | Go                                                          |
| HTTP Server        | Go `net/http`                                               |
| WebSocket          | `github.com/coder/websocket`                                |
| Network Capture    | Linux AF_PACKET (raw sockets), no libpcap dependency        |
| Initial Storage    | JSON files (`data/settings.json`, `data/integrations.json`) |
| Frontend           | React, TypeScript, and Vite                                 |
| Live Updates       | WebSocket (single `/ws` endpoint)                           |
| Configuration      | Environment variables, `.env` file, and CLI flags           |
| Service Management | systemd (planned)                                           |
| Testing            | Go testing                                                  |

The storage layer is intended to be replaceable. SQLite (with FTS5) is a candidate for event storage; PostgreSQL or ClickHouse may be considered later if workload measurements show that JSON-based persistence is insufficient.

## Requirements

### Development Environment

- Linux development environment.
- Go toolchain compatible with the version declared in `go.mod` (Go 1.27.2).
- Git.
- Node.js and npm for frontend development.
- Root privileges or `CAP_NET_RAW` for live packet capture.

On Debian or Ubuntu:

```bash
sudo apt update

sudo apt install -y \
  git \
  build-essential \
  pkg-config
```

Install Go and Node.js separately if they are not already available. Note: libpcap is not required by the current code, which uses raw AF_PACKET sockets directly.

## Getting Started

### 1. Clone the Repository

```bash
git clone <REPOSITORY_URL> rasadbin
cd rasadbin
```

Replace `<REPOSITORY_URL>` with the actual repository URL.

### 2. Install Go Dependencies

The module is declared as `rasadbin` in `go.mod`. The only external dependency is the WebSocket library:

```bash
go mod tidy
```

### 3. Build the Web UI

The Go server serves static assets from `webui/dist`. Build them first:

```bash
cd webui
npm install
npm run build
cd ..
```

### 4. Run the Application

The main package lives at `cmd/app`. From the repository root:

```bash
go run ./cmd/app help
go run ./cmd/app version
go run ./cmd/app run
```

The CLI reports the product name `Rasadbin`, the command name `rasadbin`, the version constant from `cmd/app/version.go`, and the Git commit hash injected at build time (or `dev` when built without `scripts/build.sh`).

By default, the HTTP server listens on:

```text
127.0.0.1:8080
```

A convenience script is available:

```bash
./scripts/run_server.sh
```

This runs the server on `127.0.0.1:9090`.

On first run, if `ADMIN_PASSWORD` is not set, a random admin password is generated and printed to stderr. Set it via `.env` or the environment to choose your own (minimum 10 characters).

### 5. Verify the Health Endpoint

In another terminal:

```bash
curl -i http://127.0.0.1:8080/healthz
```

The implementation returns an HTTP 200 response similar to:

```json
{
  "status": "ok",
  "service": "rasadbin",
  "version": "0.1.8"
}
```

This endpoint currently checks basic HTTP service availability. It does not yet guarantee that collectors, storage, or detection components are operational.

### 6. Build the Binary

The build script injects the current short Git commit hash into the binary via `-ldflags -X main.commit=...`. The application version is a compile-time constant in `cmd/app/version.go` and is not overridden by the build.

```bash
./scripts/build.sh
```

This produces:

```text
build/rasadbin
```

To build manually with the same effect:

```bash
mkdir -p build
COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
CGO_ENABLED=1 go build \
  -ldflags "-X main.commit=${COMMIT}" \
  -o build/rasadbin \
  ./cmd/app
```

Run the compiled binary:

```bash
./build/rasadbin version
./build/rasadbin run
```

`version` output has the form:

```text
Rasadbin 0.1.8 (<commit>)
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

# Build the application (with commit hash injected)
./scripts/build.sh

# Type-check and build the frontend
cd webui && npm run typecheck && npm run build
```

Use `golangci-lint` when configured for the repository.

## Configuration

Rasadbin resolves configuration with the following precedence (highest wins):

1. Explicit CLI flags
2. Real environment variables
3. Values from the `.env` file (loaded into the environment)
4. Built-in defaults

### Bootstrap Configuration

Loaded at startup from `.env`, the environment, and CLI flags. See `.env.example`.

| Variable            | Flag                  | Default             | Description                                 |
| ------------------- | --------------------- | ------------------- | ------------------------------------------- |
| `HTTP_HOST`         |                       | `127.0.0.1`         | HTTP bind host                              |
| `HTTP_PORT`         |                       | `8080`              | HTTP bind port                              |
| `DATA_DIR`          | `--data-dir`          | `./data`            | Directory for persisted settings            |
| `WEBUI_DIR`         | `--webui-dir`         | `webui/dist`        | Path to built web UI assets                 |
| `ADMIN_PASSWORD`    |                       | (generated)         | Initial admin password (min. 10 characters) |
| `CAPTURE_INTERFACE` | `--capture-interface` | (collector default) | Linux interface for packet capture          |
| `ENV_FILE`          |                       | `.env`              | Path to the environment file                |

The `--listen` flag overrides `HTTP_HOST`/`HTTP_PORT` directly.

### Runtime Settings

Editable from the admin **Settings** page and persisted to `DATA_DIR/settings.json`:

| Setting           | Default    | Range                     |
| ----------------- | ---------- | ------------------------- |
| `instance_name`   | `Rasadbin` | 1–64 chars                |
| `log_level`       | `info`     | debug/info/warn/error     |
| `session_minutes` | `60`       | 5–1440                    |
| `retention_days`  | `30`       | 1–3650 (not enforced yet) |
| `refresh_seconds` | `2`        | 1–60                      |

### Integration State

Enable/disable state and alerting toggles are persisted to `DATA_DIR/integrations.json`.

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
- Grant packet-capture and log-reading permissions only where required (`CAP_NET_RAW` for network capture).
- Validate and sanitize untrusted event data.
- Protect management endpoints against unauthorized changes.
- Record sensitive administrative operations in an audit log (login, settings changes, integration toggles, password changes are logged).
- Apply retention limits and protect stored event data.
- Avoid collecting or retaining packet payloads unless explicitly required (the network collector emits L3/L4 metadata only).
- Do not treat a successful health check as proof that the entire SIEM is functioning correctly.

Packet visibility depends on the network interface and deployment topology. Capturing on an ordinary interface does not automatically expose traffic between other hosts. A network TAP, mirrored switch port, or suitable observation point may be required.

### Authentication Notes

- Users and sessions are held in memory only; they are lost on restart.
- Passwords are hashed with PBKDF2-SHA256 (600,000 iterations).
- Five failed attempts trigger a 5-minute lockout per IP (login) or per username (password change).
- Changing a password revokes all sessions for that user.
- Session tokens are stored in `sessionStorage` by the web client.

## Project Structure

```text
rasadbin/
├── cmd/
│   └── app/
│       ├── main.go          # CLI entry, HTTP server, graceful shutdown
│       └── version.go       # Product name, command name, version
├── internal/
│   ├── collector/
│   │   └── network/
│   │       ├── collector_linux.go       # AF_PACKET capture (Linux)
│   │       ├── collector_linux_test.go  # Ethernet/IPv4/TCP decoding tests
│   │       └── collector_other.go       # Stub for non-Linux builds
│   ├── config/
│   │   ├── config.go        # Bootstrap config (flags/env/.env)
│   │   └── env.go           # .env file loader
│   └── web/
│       ├── auth.go          # In-memory users, sessions, brute-force limits
│       ├── hub.go           # WebSocket hub, events, stats
│       ├── integrations.go  # Integration registry and persistence
│       ├── integrations_test.go
│       ├── server.go        # HTTP routes, static assets, network capture start
│       ├── settings.go      # Runtime settings persistence
│       └── ws.go            # WebSocket protocol (login, auth, dispatch)
├── data/
│   └── integrations.json    # Persisted integration state (generated)
├── scripts/
│   ├── build.sh             # Build with commit injection
│   └── run_server.sh        # Run on 127.0.0.1:9090
├── webui/
│   ├── src/
│   │   ├── components/      # RequireAuth, TopBar
│   │   ├── lib/             # types.ts, ws.ts (WebSocket client)
│   │   ├── pages/           # Dashboard, Integrations, IntegrationWorkspace, Login, Settings
│   │   ├── App.tsx          # Routes
│   │   ├── main.tsx
│   │   └── styles.css
│   ├── index.html
│   ├── package.json
│   ├── tsconfig.json
│   └── vite.config.ts
├── .env.example
├── .gitignore
├── go.mod
└── README.md
```

Directories marked as planned in earlier versions (`internal/pipeline`, `internal/detection`, `internal/storage`, `internal/alert`, `internal/search`, `internal/api`, `configs/rules`, `deploy`, `migrations`, `tests`, `web`) do not exist yet.

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

## Built-in Integration Control Plane

The Web UI includes an admin-only **Integrations** page. Built-in source definitions are persisted in `DATA_DIR/integrations.json` and can be enabled/disabled independently:

- **Network packets** — AF_PACKET capture with L2–L4 protocol normalization; emits metadata-only events. Requires `CAP_NET_RAW`/root.
- **systemd journal** — journal field normalization and host/auth/service detection packs (collector pending).
- **Syslog files** — syslog parsing and SSH/sudo/kernel detection packs (collector pending).
- **Service logs** — service-specific parser adapters and service-health detection packs (collector pending).

Each integration exposes its collector, processor, detections, alerting switch, and a dedicated workspace route (`/integrations/<id>`). The WebSocket control messages are `integrations.get`, `integration.update`, and `integration.events`.

## Initial Detection Engine

Rules are loaded from `DATA_DIR/rules` (default `./data/rules`) on startup. Supported formats are YAML (`.yaml`, `.yml`) and JSON (`.json`). A rule supports `id`, `title`, `description`, `severity`, `enabled`, `sources`, `match_any`, `kind`, `threshold`, `window_seconds`, and `dedup_seconds`. Three starter rules are shipped in `data/rules/` and should be copied into the runtime data directory when deploying from a packaged binary.

Alerts are emitted on the authenticated WebSocket stream as `{"type":"alert","data":...}` and can be requested with `{"type":"alerts.get"}`. Alert state is currently in memory; persistent alert storage, status workflow, and hot reload are TODOs. Port-scan detection counts distinct destination ports per source in the configured window; SSH/auth detections use matching authentication log messages.
