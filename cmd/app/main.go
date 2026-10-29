// <file path="cmd/app/main.go">
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"rasadbin/internal/config"
	"rasadbin/internal/storage"
	"rasadbin/internal/web"
)

func main() {
	os.Exit(execute(os.Args[1:]))
}

func execute(args []string) int {
	if len(args) == 0 {
		printUsage()
		return 0
	}

	switch args[0] {
	case "run":
		if err := runCommand(args[1:]); err != nil {
			slog.Error("application stopped", "error", err)
			return 1
		}
		return 0

	case "version":
		fmt.Printf("%s %s (%s)\n", APP_NAME, APP_VERSION, commit)
		return 0

	case "help", "-h", "--help":
		printUsage()
		return 0

	// TODO: Implement "check-config" after the configuration
	// package is available.
	//
	// TODO: Implement "sources" to list configured collectors.
	//
	// TODO: Implement "rules" to validate and manage detection rules.
	//
	// TODO: Implement "capture" for live network capture.
	//
	// TODO: Implement "replay" for offline PCAP analysis.
	//
	// TODO: Implement "doctor" to diagnose permissions,
	// dependencies, storage and collector health.

	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", args[0])
		printUsage()
		return 2
	}
}

func runCommand(args []string) error {
	cfg, err := config.Load(args)
	if err != nil {
		return err
	}

	// TODO: Load and validate application configuration.
	// TODO: Initialize persistent storage and run migrations.
	// TODO: Initialize the normalized event schema.
	// TODO: Create bounded ingestion queues and the event pipeline.
	// TODO: Initialize network, journald and file-log collectors.
	// TODO: Initialize enrichment and detection engines.
	// TODO: Initialize alert and case management.
	// TODO: Persist users (the web UI keeps them in memory for now).
	// TODO: Expose metrics and collector health information.
	// TODO: Apply least-privilege permissions for Linux collectors.

	// The log level can be changed at runtime from the admin settings page.
	logLevel := new(slog.LevelVar)
	logLevel.Set(slog.LevelInfo)

	logger := slog.New(slog.NewTextHandler(
		os.Stdout,
		&slog.HandlerOptions{
			Level: logLevel,
		},
	))
	slog.SetDefault(logger)

	printWelcome(cfg)

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	ui, err := web.New(web.Config{
		DataDir:       cfg.DataDir,
		AdminPassword: cfg.AdminPassword,
		Version:       APP_VERSION,
		Commit:        commit,
		LogLevel:      logLevel,
		WebUIDir:      cfg.WebUIDir,
	})
	if err != nil {
		return fmt.Errorf("web UI: %w", err)
	}
	store, err := storage.Open(cfg.DB)
	if err != nil {
		return fmt.Errorf("open event store: %w", err)
	}
	defer store.Close()
	ui.SetStore(ctx, store, store)
	go ui.Run(ctx)
	if err := ui.StartNetworkCapture(ctx, cfg.CaptureInterfaces); err != nil {
		slog.Warn("network packet capture unavailable", "error", err)
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(
			`{"status":"ok","service":"` + APP_COMMAND_NAME + `","version":"` +
				APP_VERSION + `"}` + "\n",
		))
	})

	// Pages (/login, /dashboard, /settings), static assets and the
	// WebSocket endpoint (/ws). There is deliberately no REST API.
	mux.Handle("/", ui.Handler())

	// TODO: Add GET /readyz for dependency readiness.
	// TODO: Collectors call ui.Publish(web.Event{...}) to feed the
	// dashboard's live event list.

	server := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		// No WriteTimeout: it would also apply to hijacked WebSocket
		// connections. The WebSocket layer enforces its own write deadlines.
		IdleTimeout: 60 * time.Second,
	}

	serverErrors := make(chan error, 1)

	go func() {
		slog.Info(
			"starting HTTP server",
			"service", APP_NAME,
			"version", APP_VERSION,
			"commit", commit,
			"address", cfg.ListenAddr,
		)

		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
			return
		}

		serverErrors <- nil
	}()

	select {
	case err := <-serverErrors:
		if err != nil {
			return fmt.Errorf("HTTP server: %w", err)
		}
		return nil

	case <-ctx.Done():
		slog.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		slog.Warn("graceful shutdown failed", "error", err)

		// TODO: Stop collectors and workers in a controlled order.
		// TODO: Flush pending events and persist checkpoints.
		// TODO: Close storage and release capture resources.

		if closeErr := server.Close(); closeErr != nil {
			return errors.Join(err, closeErr)
		}
		return err
	}

	// Let the hub drain queued writes before closing SQLite.
	ui.DrainStore(5 * time.Second)
	if err := store.Close(); err != nil {
		slog.Warn("closing event store", "error", err)
	}

	// TODO: Stop collectors before closing the event pipeline.
	// TODO: Drain bounded queues within a configurable timeout.
	// TODO: Flush alerts and close the storage backend.

	slog.Info("shutdown completed")
	return nil
}

func printWelcome(cfg config.Config) {
	uiURL := "http://" + cfg.ListenAddr

	fmt.Println()

	fmt.Printf("  %s v%s (%s) — Linux-first SIEM\n", APP_NAME, APP_VERSION, commit)
	fmt.Println()
	fmt.Println("  ─────────────────────────────────────────────────────────────")
	fmt.Println()
	fmt.Printf("  Web UI        %s\n", uiURL)
	fmt.Printf("  Health check  %s/healthz\n", uiURL)
	fmt.Printf("  WebSocket     ws://%s/ws\n", cfg.ListenAddr)
	fmt.Printf("  Data dir      %s\n", cfg.DataDir)
	fmt.Printf("  Env file      %s\n", cfg.EnvFile)
	fmt.Printf("  Database      %s (%s)\n", cfg.DB.Driver, cfg.DB.DSN)

	if len(cfg.CaptureInterfaces) > 0 {
		fmt.Printf("  Capture iface %s\n", cfg.CaptureInterfaces)
	}
	fmt.Println()
	fmt.Println("  ─────────────────────────────────────────────────────────────")
	fmt.Println()
	fmt.Println("  Quick start:")
	fmt.Printf("    1. Open %s in your browser\n", uiURL)
	fmt.Println("    2. Sign in with the admin credentials")
	fmt.Println("    3. Enable integrations under Integrations")
	fmt.Println()
	fmt.Println("  Notes:")
	fmt.Println("    • The admin password is printed to stderr if ADMIN_PASSWORD is unset.")
	fmt.Println("    • Network capture requires CAP_NET_RAW / root and a Linux host.")
	fmt.Println("    • Integration collectors are pending; the UI reports their status.")
	fmt.Println("    • Bind to 127.0.0.1 by default. Do not expose without TLS + auth.")
	fmt.Println()
	fmt.Println("  Press Ctrl+C to stop.")
	fmt.Println()
}

func printUsage() {
	fmt.Printf(`%[1]s %[2]s

Run options (values usually come from .env; flags override):
  --listen            HTTP listen address (env HTTP_HOST/HTTP_PORT, default 127.0.0.1:8080)
  --data-dir          Directory for persisted settings (env DATA_DIR, default ./data)
  --webui-dir         Path to built web UI assets (env WEBUI_DIR, default webui/dist)
  --capture-interface Linux interface for packet capture (env CAPTURE_INTERFACE)

Environment file:
  ENV_FILE   Path to .env (default ./.env; missing file is OK)

Environment (.env or real env):
  HTTP_HOST, HTTP_PORT, DATA_DIR, WEBUI_DIR, ADMIN_PASSWORD, CAPTURE_INTERFACE
`, APP_NAME, APP_VERSION, APP_COMMAND_NAME)
}
