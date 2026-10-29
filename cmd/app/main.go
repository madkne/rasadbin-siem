package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// TODO: Replace these constants with build-time values.
// Example:
//
// go build -ldflags "-X main.appVersion=0.2.0"
//
// appVersion must be a variable if it is to be overridden
// using -ldflags.

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
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	listenAddr := fs.String(
		"listen",
		"127.0.0.1:8080",
		"HTTP listen address",
	)

	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}

	if *listenAddr == "" {
		return errors.New("listen address cannot be empty")
	}

	// TODO: Load and validate application configuration.
	// TODO: Initialize persistent storage and run migrations.
	// TODO: Initialize the normalized event schema.
	// TODO: Create bounded ingestion queues and the event pipeline.
	// TODO: Initialize network, journald and file-log collectors.
	// TODO: Initialize enrichment and detection engines.
	// TODO: Initialize alert and case management.
	// TODO: Initialize authentication and authorization.
	// TODO: Register API routes and embed the production web UI.
	// TODO: Expose metrics and collector health information.
	// TODO: Apply least-privilege permissions for Linux collectors.

	logger := slog.New(slog.NewTextHandler(
		os.Stdout,
		&slog.HandlerOptions{
			Level: slog.LevelInfo,
		},
	))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

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

	// TODO: Add GET /readyz for dependency readiness.
	// TODO: Add GET /api/v1/overview.
	// TODO: Add GET /api/v1/events and event details.
	// TODO: Add GET /api/v1/alerts and alert management.
	// TODO: Add CRUD endpoints for sources and detection rules.
	// TODO: Add GET /api/v1/network/interfaces.
	// TODO: Add SSE endpoint for live events and alerts.
	// TODO: Protect management endpoints with authentication,
	// authorization, request limits and audit logging.

	server := &http.Server{
		Addr:              *listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serverErrors := make(chan error, 1)

	go func() {
		slog.Info(
			"starting HTTP server",
			"service", APP_NAME,
			"version", APP_VERSION,
			"commit", commit,
			"address", *listenAddr,
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

	// TODO: Stop collectors before closing the event pipeline.
	// TODO: Drain bounded queues within a configurable timeout.
	// TODO: Flush alerts and close the storage backend.

	slog.Info("shutdown completed")
	return nil
}

func printUsage() {
	fmt.Printf(`%s %s

Usage:
  %s <command> [options]

Commands:
  run       Start the SIEM service
  version   Print version information
  help      Show this help

Run options:
  --listen  HTTP listen address (default: 127.0.0.1:8080)

Examples:
  %s run
  %s run --listen 127.0.0.1:9090
  %s version
`, APP_NAME, APP_VERSION, APP_COMMAND_NAME)
}
