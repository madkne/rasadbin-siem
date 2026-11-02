// Package web serves the Rasadbin web UI. All dynamic communication happens
// over a single WebSocket endpoint (/ws); there is no REST API.
package web

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"rasadbin/internal/asset"
	"rasadbin/internal/asset/enrichment"
	"rasadbin/internal/asset/enrichment/providers"
	"rasadbin/internal/collector/journal"
	"rasadbin/internal/collector/network"
	"rasadbin/internal/collector/servicelog"
	"rasadbin/internal/collector/syslog"
	"rasadbin/internal/detection"
	"rasadbin/internal/profile"
	"strings"
	"time"
)

// Config configures the web UI.
type Config struct {
	AuthRepository    AuthRepository
	DataDir           string
	AdminPassword     string // generated and printed to stderr when empty
	Version           string
	Commit            string
	LogLevel          *slog.LevelVar // adjusted by the admin settings page
	WebUIDir          string         // path to webui/dist (defaults to "webui/dist")
	ServiceLogPaths   []string
	CaptureInterfaces []string
}

// Server is the web UI: pages, static assets and the WebSocket hub.
type Server struct {
	hub              *Hub
	auth             *Auth
	settings         *SettingsStore
	integrations     *IntegrationStore
	static           fs.FS
	store            EventQuerier
	alertStore       AlertStore
	baseCtx          context.Context
	networkCaptures  []*network.Collector
	collectorManager *CollectorManager
	detection        *detection.Engine
	serviceLogPaths  []string
	profiles         *profile.Manager
	captureIfaces    []string
	assets           *asset.Service
	enrichment       *enrichment.Engine
}

// New builds the web UI server.
func New(cfg Config) (*Server, error) {
	if cfg.LogLevel == nil {
		cfg.LogLevel = new(slog.LevelVar)
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "./data"
	}
	if cfg.WebUIDir == "" {
		cfg.WebUIDir = filepath.Join("webui", "dist")
	}

	levelVar := cfg.LogLevel
	store, err := LoadSettings(
		filepath.Join(cfg.DataDir, "settings.json"),
		func(s Settings) { levelVar.Set(parseLevel(s.LogLevel)) },
	)
	if err != nil {
		return nil, fmt.Errorf("load settings: %w", err)
	}

	integrations, err := LoadIntegrationStore(cfg.DataDir)
	if err != nil {
		return nil, fmt.Errorf("load integrations: %w", err)
	}

	password := cfg.AdminPassword
	if password == "" {
		usersExist := false
		if cfg.AuthRepository != nil {
			var checkErr error
			usersExist, checkErr = cfg.AuthRepository.HasAuthUsers()
			if checkErr != nil {
				return nil, fmt.Errorf("check persisted auth users: %w", checkErr)
			}
		}
		if !usersExist {
			tok := randomToken()
			if len(tok) > 20 {
				tok = tok[:20]
			}
			password = tok
			fmt.Fprintf(os.Stderr,
				"rasadbin: generated initial admin password (set ADMIN_PASSWORD to choose your own): %s\\n",
				password)
		}
	}
	auth, err := NewAuthWithRepository(password, func() time.Duration {
		return time.Duration(store.Get().SessionMinutes) * time.Minute
	}, cfg.AuthRepository)
	if err != nil {
		return nil, err
	}

	// Load static assets from webui/dist on disk.
	static := os.DirFS(cfg.WebUIDir)
	if _, err := fs.Stat(static, "index.html"); err != nil {
		return nil, fmt.Errorf("web UI assets not found in %q (run `npm run build` in webui): %w",
			cfg.WebUIDir, err)
	}

	rulesDir := filepath.Join(cfg.DataDir, "rules")
	if err := os.MkdirAll(rulesDir, 0700); err != nil {
		return nil, fmt.Errorf("create detection rules directory: %w", err)
	}
	engine, err := detection.New(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("load detection rules: %w", err)
	}

	srv := &Server{
		hub:             NewHub(cfg.Version, cfg.Commit),
		auth:            auth,
		settings:        store,
		integrations:    integrations,
		static:          static,
		detection:       engine,
		serviceLogPaths: cfg.ServiceLogPaths,
		captureIfaces:   cfg.CaptureInterfaces,
	}
	srv.integrations.notify = func(typ string, data any) {
		srv.hub.Broadcast(typ, data)
	}
	var enrichmentEngine *enrichment.Engine
	srv.assets = asset.NewService(asset.Options{}, func(batch []asset.Asset) {
		srv.hub.broadcastAuthenticated("assets.changed", batch)
		for _, item := range batch {
			if item.EnrichmentStatus == "pending" || item.EnrichmentStatus == "" {
				if enrichmentEngine != nil {
					enrichmentEngine.Enqueue(item.ID)
				}
			}
		}
	})
	enrichmentEngine, err = enrichment.New(srv.assets, []enrichment.Provider{
		providers.DNSReverse{},
		providers.LinuxNeighborTable{},
		providers.PassiveServices{},
	}, enrichment.Config{Workers: 2, QueueSize: 512, ActiveAllowed: srv.activeEnrichmentAllowed})
	if err != nil {
		return nil, fmt.Errorf("initialize asset enrichment: %w", err)
	}
	srv.enrichment = enrichmentEngine
	srv.assets.SetLinkHandler(func(changed []asset.Link, removed []string) {
		srv.hub.broadcastTopology("topology.changed",
			map[string]any{"links": changed, "removed": removed})
	})

	profiles, err := newProfileManager(cfg.DataDir, engine, integrations, srv.collectorManager)
	if err != nil {
		return nil, fmt.Errorf("initialize security profiles: %w", err)
	}
	srv.profiles = profiles

	return srv, nil
}

// SetStore wires the persistent event store (call before Run/Handler).
func (s *Server) SetStore(ctx context.Context, q EventQuerier, app EventStore) {
	s.baseCtx = ctx
	s.store = q
	if app != nil {
		s.hub.SetStore(app)
		if alerts, ok := app.(AlertStore); ok {
			s.alertStore = alerts
		}
		if st, ok := app.(asset.Store); ok {
			if err := s.assets.Attach(ctx, st); err != nil {
				slog.Error("load assets failed", "error", err)
			}
		}
	}
}

// DrainStore waits up to timeout for queued events to be persisted.
func (s *Server) DrainStore(timeout time.Duration) {
	s.hub.drainStore(timeout)
	_ = s.assets.Flush(context.Background())
}

// Run drives periodic dashboard pushes until ctx is cancelled.
func (s *Server) Run(ctx context.Context) {
	go s.assets.Run(ctx)
	if s.enrichment != nil {
		go s.enrichment.Run(ctx)
	}
	s.hub.Run(ctx, func() time.Duration {
		return time.Duration(s.settings.Get().RefreshSeconds) * time.Second
	}, s.auth)
}

// activeEnrichmentAllowed is a second server-side safety gate. Even if a
// future active provider is registered, it cannot run unless the admin enabled
// active enrichment and explicitly scoped the target IP in Settings.
func (s *Server) activeEnrichmentAllowed(a asset.Asset) bool {
	if s == nil || s.settings == nil {
		return false
	}
	settings := s.settings.Get()
	if !settings.ActiveEnrichmentEnabled || len(settings.ActiveEnrichmentCIDRs) == 0 {
		return false
	}
	for _, raw := range a.IPs {
		ip, err := netip.ParseAddr(raw)
		if err != nil {
			continue
		}
		for _, cidr := range settings.ActiveEnrichmentCIDRs {
			prefix, err := netip.ParsePrefix(cidr)
			if err == nil && prefix.Contains(ip) {
				return true
			}
		}
	}
	return false
}

// Publish adds an event to the dashboard's live feed. Collectors call this.
func (s *Server) Publish(e Event) {
	if processed, ok := s.integrations.ProcessEvent(e); ok {
		s.hub.Publish(processed)
		s.assets.ObserveEvent(processed.Source, processed.Message, processed.Time)
		if s.detection != nil {
			for _, alert := range s.detection.Process(detection.Event{
				Time: processed.Time, Source: processed.Source,
				Severity: processed.Severity, Message: processed.Message,
			}) {
				s.PublishAlert(alert)
			}
		}
	}
}

// PublishAlert persists a detection result before notifying connected clients.
func (s *Server) PublishAlert(alert detection.Alert) {
	if s.alertStore != nil {
		ctx := s.baseCtx
		if ctx == nil {
			ctx = context.Background()
		}
		writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		persisted, err := s.alertStore.UpsertAlert(writeCtx, alert)
		cancel()
		if err != nil {
			slog.Error("persist alert failed", "alert_id", alert.ID, "error", err)
		} else {
			alert = persisted
		}
	}
	s.hub.PublishAlert(alert)
}

// RecentAlerts reads durable alerts when storage is configured, otherwise it
// falls back to the in-memory engine for tests and embedded use.
func (s *Server) RecentAlerts(limit int) []detection.Alert {
	if s.alertStore != nil {
		ctx := s.baseCtx
		if ctx == nil {
			ctx = context.Background()
		}
		items, _, err := s.alertStore.ListAlerts(ctx, AlertQuery{Limit: limit})
		if err != nil {
			slog.Error("load alerts failed", "error", err)
			return nil
		}
		return items
	}
	if s.detection == nil {
		return nil
	}
	return s.detection.Recent(limit)
}

// Integrations returns a snapshot of built-in integration configuration.
func (s *Server) Integrations() []Integration { return s.integrations.List() }

// Handler returns the page, static asset and WebSocket routes.
//
// The React app in webui is a client-side routed SPA, so every page route
// (/login, /dashboard, /settings) serves the same index.html and the router
// takes over in the browser.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// root
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	})

	index := s.page()
	// exact app pages
	for _, name := range []string{"login", "dashboard", "settings", "integrations", "events", "alerts", "rules", "network", "systemd", "syslog", "services", "assetsman", "topology"} {
		mux.HandleFunc("GET /"+name, index)
	}

	// Static assets built by Vite (JS, CSS, etc.).
	mux.Handle("GET /assets/", http.FileServerFS(s.static))
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(s.static)))

	mux.HandleFunc("GET /ws", s.serveWS)
	// SPA fallback for refresh / deep link navigation
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ws" || strings.HasPrefix(r.URL.Path, "/assets/") ||
			strings.HasPrefix(r.URL.Path, "/static/") ||
			strings.HasPrefix(r.URL.Path, "/topology/") {
			http.NotFound(w, r)
			return
		}

		// serve index for client-side routes
		b, err := fs.ReadFile(s.static, "index.html")
		if err != nil {
			http.Error(w, "web UI not built", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(b)
	})
	return secureHeaders(mux)
}

func (s *Server) page() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, err := fs.ReadFile(s.static, "index.html")
		if err != nil {
			http.Error(w, "web UI not built", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(b)
	}
}

// StartNetworkCapture starts the Linux packet collector when explicitly enabled.
// The caller should invoke this once after constructing the server. Capture needs
// CAP_NET_RAW/root and is intentionally not started implicitly by New().

func (s *Server) StartNetworkCapture(ctx context.Context, ifaces []string) error {
	item, ok := s.integrations.Get("network-packets")
	if !ok || !item.Enabled {
		return nil
	}
	if len(ifaces) == 0 {
		ifaces = []string{""} // collector default ("any")
	}
	var firstErr error
	for _, iface := range ifaces {
		c, err := network.New(iface, func(e network.PacketEvent) {
			s.Publish(Event{Time: e.Time, Source: "network-packets", Severity: "info", Message: e.String()})
		})
		if err != nil {
			s.Publish(Event{Source: "network-packets", Severity: "high", Message: "packet capture failed to start: " + err.Error()})
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		s.networkCaptures = append(s.networkCaptures, c)
		go func(c *network.Collector) {
			if err := c.Run(ctx); err != nil && ctx.Err() == nil {
				slog.Error("network packet collector stopped", "error", err, "interface", c.Interface())
				s.Publish(Event{Source: "network-packets", Severity: "high", Message: "packet capture stopped: " + err.Error()})
			}
		}(c)
		slog.Info("network packet collector started", "interface", c.Interface())
	}
	return firstErr
}

// StartSyslogCollection tails syslog files when the integration is enabled.
// TODO(advanced): start/stop on runtime toggle instead of requiring a restart.
func (s *Server) StartSyslogCollection(ctx context.Context, paths []string) error {
	item, ok := s.integrations.Get("syslog-files")
	if !ok || !item.Enabled {
		return nil
	}
	c, err := syslog.New(paths, func(e syslog.Entry) {
		s.Publish(Event{Time: e.Time, Source: "syslog-files", Severity: e.Severity, Message: e.String()})
	})
	if err != nil {
		s.Publish(Event{Source: "syslog-files", Severity: "high", Message: "syslog collector failed to start: " + err.Error()})
		return err
	}
	go func() {
		if err := c.Run(ctx); err != nil && ctx.Err() == nil {
			slog.Error("syslog collector stopped", "error", err)
		}
	}()
	slog.Info("syslog collector started", "paths", c.Paths())
	return nil
}
func (s *Server) InitCollectorManager(ctx context.Context) error {
	m := NewCollectorManager(ctx, s.integrations)

	if err := m.Register("network-packets", func() (CollectorRunner, error) {
		ifaces := s.captureIfaces
		if len(ifaces) == 0 {
			ifaces = []string{"any"} // CAPTURE_INTERFACE unset
		}
		cols := make([]*network.Collector, 0, len(ifaces))
		for _, iface := range ifaces {
			c, err := network.New(iface, func(e network.PacketEvent) {
				s.Publish(Event{
					Time:     e.Time,
					Source:   "network-packets",
					Severity: "info",
					Message:  e.String(),
				})
			})
			if err != nil {
				return nil, err // e.g. interface does not exist
			}
			cols = append(cols, c)
		}
		return func(ctx context.Context) error {
			ctx, cancel := context.WithCancel(ctx)
			defer cancel()
			errCh := make(chan error, len(cols))
			for _, c := range cols {
				go func(c *network.Collector) { errCh <- c.Run(ctx) }(c)
			}
			var first error
			for range cols {
				if err := <-errCh; err != nil && first == nil {
					first = err
					cancel() // stop the other interfaces too
				}
			}
			return first
		}, nil
	}); err != nil {
		m.Close()
		return err
	}

	if err := m.Register("syslog-files", func() (CollectorRunner, error) {
		paths := []string{
			"/var/log/auth.log",
			"/var/log/syslog",
			"/var/log/messages",
			"/var/log/secure",
		}

		c, err := syslog.New(paths, func(e syslog.Entry) {
			s.Publish(Event{
				Time:     e.Time,
				Source:   "syslog-files",
				Severity: e.Severity,
				Message:  e.String(),
			})
		})
		if err != nil {
			return nil, err
		}
		return c.Run, nil
	}); err != nil {
		m.Close()
		return err
	}

	if err := m.Register("systemd-journal", func() (CollectorRunner, error) {
		c, err := journal.New(func(e journal.Entry) {
			s.Publish(Event{
				Time:     e.Time,
				Source:   "systemd-journal",
				Severity: e.Severity,
				Message:  e.String(),
			})
		})
		if err != nil {
			return nil, err
		}
		return c.Run, nil
	}); err != nil {
		m.Close()
		return err
	}

	if err := m.Register("service-logs", func() (CollectorRunner, error) {
		paths := s.serviceLogPaths
		if len(paths) == 0 {
			paths = servicelog.DefaultPaths
		}
		c, err := servicelog.New(paths, func(e servicelog.Entry) {
			s.Publish(Event{
				Time:     e.Time,
				Source:   "service-logs",
				Severity: e.Severity,
				Message:  e.String(),
			})
		})
		if err != nil {
			return nil, err
		}
		return c.Run, nil
	}); err != nil {
		m.Close()
		return err
	}

	s.collectorManager = m
	m.Reconcile()
	return nil
}

func (s *Server) CloseCollectors() {
	if s.collectorManager != nil {
		s.collectorManager.Close()
	}
}
