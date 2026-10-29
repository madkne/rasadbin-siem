// Package web serves the Rasadbin web UI. All dynamic communication happens
// over a single WebSocket endpoint (/ws); there is no REST API.
package web

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

//go:embed assets
var assetsFS embed.FS

// Config configures the web UI.
type Config struct {
	DataDir       string
	AdminPassword string // generated and printed to stderr when empty
	Version       string
	Commit        string
	LogLevel      *slog.LevelVar // adjusted by the admin settings page
}

// Server is the web UI: pages, static assets and the WebSocket hub.
type Server struct {
	hub      *Hub
	auth     *Auth
	settings *SettingsStore
	pages    map[string][]byte
	static   fs.FS
}

// New builds the web UI server.
func New(cfg Config) (*Server, error) {
	if cfg.LogLevel == nil {
		cfg.LogLevel = new(slog.LevelVar)
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "./data"
	}

	store, err := LoadSettings(
		filepath.Join(cfg.DataDir, "settings.json"),
		func(s Settings) { cfg.LogLevel.Set(parseLevel(s.LogLevel)) },
	)
	if err != nil {
		return nil, fmt.Errorf("load settings: %w", err)
	}

	password := cfg.AdminPassword
	if password == "" {
		password = randomToken()[:20]
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

	pages := make(map[string][]byte)
	for _, name := range []string{"login", "dashboard", "settings"} {
		b, err := assetsFS.ReadFile("assets/pages/" + name + ".html")
		if err != nil {
			return nil, err
		}
		pages[name] = b
	}

	static, err := fs.Sub(assetsFS, "assets/static")
	if err != nil {
		return nil, err
	}

	return &Server{
		hub:      NewHub(cfg.Version, cfg.Commit),
		auth:     auth,
		settings: store,
		pages:    pages,
		static:   static,
	}, nil
}

// Run drives periodic dashboard pushes until ctx is cancelled.
func (s *Server) Run(ctx context.Context) {
	s.hub.Run(ctx, func() time.Duration {
		return time.Duration(s.settings.Get().RefreshSeconds) * time.Second
	}, s.auth)
}

// Publish adds an event to the dashboard's live feed. Collectors call this.
func (s *Server) Publish(e Event) { s.hub.Publish(e) }

// Handler returns the page, static asset and WebSocket routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	})
	for _, name := range []string{"login", "dashboard", "settings"} {
		mux.HandleFunc("GET /"+name, s.page(name))
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(s.static)))
	mux.HandleFunc("GET /ws", s.serveWS)

	return secureHeaders(mux)
}

func (s *Server) page(name string) http.HandlerFunc {
	body := s.pages[name]
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(body)
	}
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy",
			"default-src 'self'; connect-src 'self'; img-src 'self' data:; "+
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
