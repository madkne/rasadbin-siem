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
	"runtime"
	"path/filepath"
	"strings"
	"time"
)

// DBConfig is the resolved database configuration.
type DBConfig struct {
	Driver          string // sqlite | postgres | mysql
	DSN             string // driver-specific DSN / file path
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	LogLevel        string // silent | error | warn | info

}

// Config is the immutable process configuration resolved at startup.
type Config struct {
	ListenAddr        string
	DataDir           string
	WebUIDir          string
	AdminPassword     string
	CaptureInterfaces []string // empty = collector default
	EnvFile           string   // path actually loaded, for logging
	DB                DBConfig
	SyslogPaths       []string
	MaxGoroutines     int
}

const defaultSyslogPaths = "/var/log/auth.log,/var/log/syslog,/var/log/messages,/var/log/secure"

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

	dbDriver := fs.String("db-driver", envOr("DB_DRIVER", "sqlite"),
		"database driver: sqlite|postgres|mysql (overrides DB_DRIVER)")
	dbDSN := fs.String("db-dsn", os.Getenv("DB_DSN"),
		"database DSN; sqlite defaults to DATA_DIR/rasadbin.db (overrides DB_DSN)")
	dbLogLevel := fs.String("db-log-level", envOr("DB_LOG_LEVEL", "warn"),
		"gorm log level: silent|error|warn|info (overrides DB_LOG_LEVEL)")
	syslogPaths := fs.String("syslog-paths", envOr("SYSLOG_PATHS", defaultSyslogPaths),
		"comma-separated syslog files to tail (overrides SYSLOG_PATHS)")
	maxGoroutines := fs.Int("max-goroutines", envInt("MAX_GOROUTINES", runtime.NumCPU()),
		"maximum number of OS threads / goroutines to use (overrides MAX_GOROUTINES)")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}
	if fs.NArg() != 0 {
		return Config{}, fmt.Errorf("unexpected arguments: %v", fs.Args())
	}

	dsn := strings.TrimSpace(*dbDSN)
	if strings.EqualFold(*dbDriver, "sqlite") && dsn == "" {
		dsn = filepath.Join(strings.TrimSpace(*dataDir), "rasadbin.db")
	}
	if strings.EqualFold(*dbDriver, "sqlite") && !filepath.IsAbs(dsn) && !strings.HasPrefix(dsn, ".") {
		// keep relative-to-cwd DSNs as-is; only join DATA_DIR when clearly a bare filename
	}
	db := DBConfig{
		Driver:          strings.ToLower(strings.TrimSpace(*dbDriver)),
		DSN:             dsn,
		MaxOpenConns:    envInt("DB_MAX_OPEN_CONNS", 10),
		MaxIdleConns:    envInt("DB_MAX_IDLE_CONNS", 5),
		ConnMaxLifetime: envDuration("DB_CONN_MAX_LIFETIME", time.Hour),
		LogLevel:        strings.ToLower(strings.TrimSpace(*dbLogLevel)),
	}
	cfg := Config{
		ListenAddr:        strings.TrimSpace(*listenAddr),
		DataDir:           strings.TrimSpace(*dataDir),
		WebUIDir:          strings.TrimSpace(*webUIDir),
		AdminPassword:     os.Getenv("ADMIN_PASSWORD"),
		CaptureInterfaces: splitInterfaces(*captureInterface),
		EnvFile:           envFile,
		DB:                db,
		SyslogPaths:       splitList(*syslogPaths),
		MaxGoroutines:     *maxGoroutines,
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	if cfg.MaxGoroutines > 0 {
		runtime.GOMAXPROCS(cfg.MaxGoroutines)
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
	switch c.DB.Driver {
	case "sqlite", "postgres", "mysql":
	default:
		return fmt.Errorf("unsupported DB_DRIVER %q (want sqlite, postgres or mysql)", c.DB.Driver)
	}
	if c.DB.DSN == "" {
		return errors.New("database DSN is empty (set DB_DSN)")
	}
	switch c.DB.LogLevel {
	case "silent", "error", "warn", "info":
	default:
		return errors.New("DB_LOG_LEVEL must be silent, error, warn or info")
	}
	if c.MaxGoroutines < 0 {
		return errors.New("MAX_GOROUTINES must be zero or a positive integer")
	}
	return nil
}
