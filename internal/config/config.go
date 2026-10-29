// Package config loads Rasadbin's bootstrap configuration.
//
// Precedence (highest wins):
//  1. explicit CLI flags
//  2. real environment variables
//  3. values from the .env file (loaded into the environment)
//  4. built-in defaults
//
// Runtime-editable settings (instance name, session timeout, etc.) are NOT
// here; those live in data/settings.json and are managed by the admin UI.
package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

// Config is the immutable process configuration resolved at startup.
type Config struct {
	ListenAddr       string
	DataDir          string
	WebUIDir         string
	AdminPassword    string
	CaptureInterface string // empty = collector default
	EnvFile          string // path actually loaded, for logging
}

// Load resolves configuration from .env, the environment and args.
// args is the argument slice passed to the `run` subcommand (without "run").
func Load(args []string) (Config, error) {
	envFile := os.Getenv("ENV_FILE")
	if envFile == "" {
		envFile = ".env"
	}
	if err := loadEnvFile(envFile); err != nil {
		return Config{}, fmt.Errorf("load %s: %w", envFile, err)
	}

	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	defaultListen := envOr("HTTP_HOST", "127.0.0.1") + ":" + envOr("HTTP_PORT", "8080")
	listenAddr := fs.String("listen", defaultListen,
		"HTTP listen address (overrides HTTP_HOST/HTTP_PORT from .env)")
	dataDir := fs.String("data-dir", envOr("DATA_DIR", "./data"),
		"directory for persisted settings (overrides DATA_DIR)")
	webUIDir := fs.String("webui-dir", envOr("WEBUI_DIR", "webui/dist"),
		"path to built web UI assets (overrides WEBUI_DIR)")
	captureInterface := fs.String("capture-interface", os.Getenv("CAPTURE_INTERFACE"),
		"Linux interface for packet capture (overrides CAPTURE_INTERFACE)")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if fs.NArg() != 0 {
		return Config{}, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}

	cfg := Config{
		ListenAddr:       strings.TrimSpace(*listenAddr),
		DataDir:          strings.TrimSpace(*dataDir),
		WebUIDir:         strings.TrimSpace(*webUIDir),
		AdminPassword:    os.Getenv("ADMIN_PASSWORD"),
		CaptureInterface: strings.TrimSpace(*captureInterface),
		EnvFile:          envFile,
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks required fields and constraints.
func (c Config) Validate() error {
	if c.ListenAddr == "" {
		return errors.New("listen address cannot be empty (set HTTP_HOST/HTTP_PORT or --listen)")
	}
	if c.DataDir == "" {
		return errors.New("data directory cannot be empty (set DATA_DIR or --data-dir)")
	}
	if c.WebUIDir == "" {
		return errors.New("web UI directory cannot be empty (set WEBUI_DIR or --webui-dir)")
	}
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}