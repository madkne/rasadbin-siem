// Package web serves the Rasadbin web UI. All dynamic communication happens
// over a single WebSocket endpoint (/ws); there is no REST API.
package web

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"rasadbin/internal/collector/network"
)

// Config configures the web UI.
type Config struct {
	DataDir       string
	AdminPassword string // generated and printed to stderr when empty
	Version       string
	Commit        string
	LogLevel      *slog.LevelVar // adjusted by the admin settings page
	WebUIDir      string         // path to webui/dist (defaults to "webui/dist")
}

// Server is the web UI: pages, static assets and the WebSocket hub.
type Server struct {
	hub             *Hub
	auth            *Auth
	settings        *SettingsStore
	integrations    *IntegrationStore
	static          fs.FS
	store           EventQuerier
	baseCtx         context.Context
	networkCaptures []*network.Collector
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
		tok := randomToken()
		if len(tok) > 20 {
			tok = tok[:20]
		}
		password = tok
		fmt.Fprintf(os.Stderr,
			"rasadbin: generated admin password (set RASADBIN_ADMIN_PASSWORD to choose your own): %s\n",
			password)
	}

	auth, err := NewAuth(password, func() time.Duration {
		return time.Duration(store.Get().SessionMinutes) * time.Minute
	})
	if err != nil {
		return nil, err
	}

	// Load static assets from webui/dist on disk.
	static := os.DirFS(cfg.WebUIDir)
	if _, err := fs.Stat(static, "index.html"); err != nil {
		return nil, fmt.Errorf("web UI assets not found in %q (run `npm run build` in webui): %w",
			cfg.WebUIDir, err)
	}

	return &Server{
		hub:          NewHub(cfg.Version, cfg.Commit),
		auth:         auth,
		settings:     store,
		integrations: integrations,
		static:       static,
	}, nil
}

// SetStore wires the persistent event store (call before Run/Handler).
func (s *Server) SetStore(ctx context.Context, q EventQuerier, app EventStore) {
	s.baseCtx = ctx
	s.store = q
	if app != nil {
		s.hub.SetStore(app)
	}
}

// DrainStore waits up to timeout for queued events to be persisted.
func (s *Server) DrainStore(timeout time.Duration) {
	s.hub.drainStore(timeout)
}

// Run drives periodic dashboard pushes until ctx is cancelled.
func (s *Server) Run(ctx context.Context) {
	s.hub.Run(ctx, func() time.Duration {
		return time.Duration(s.settings.Get().RefreshSeconds) * time.Second
	}, s.auth)
}

// Publish adds an event to the dashboard's live feed. Collectors call this.
func (s *Server) Publish(e Event) {
	if processed, ok := s.integrations.ProcessEvent(e); ok {
		s.hub.Publish(processed)
	}
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

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	})

	index := s.page()
	for _, name := range []string{"login", "dashboard", "settings", "integrations", "events", "alerts", "network", "systemd", "syslog", "services"} {
		mux.HandleFunc("GET /"+name, index)
	}

	// Static assets built by Vite (JS, CSS, etc.).
	mux.Handle("GET /assets/", http.FileServerFS(s.static))
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(s.static)))

	mux.HandleFunc("GET /ws", s.serveWS)

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

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; "+
				"style-src 'self' 'unsafe-inline'; "+
				"frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
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
