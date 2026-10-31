// Package storage persists normalized events so history survives restarts.
package storage

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"rasadbin/internal/config"
	"rasadbin/internal/web"
	"strings"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// Store is a durable event store backed by GORM.
type Store struct {
	db *gorm.DB
}

// Append inserts one event. Zero time is replaced with now (UTC).
func (s *Store) Append(ctx context.Context, e web.Event) error {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	row := Event{Time: e.Time.UTC(), Source: e.Source, Severity: e.Severity, Message: e.Message}
	if err := s.db.WithContext(ctx).Create(&row).Error; err != nil {
		return fmt.Errorf("insert event: %w", err)
	}
	return nil
}

// Query mirrors web.Hub.Search semantics against full history.
func (s *Store) Query(ctx context.Context, q web.SearchQuery) (web.SearchResult, error) {
	start := time.Now()
	db := s.db.WithContext(ctx).Model(&Event{})

	if !q.From.IsZero() {
		db = db.Where("time >= ?", q.From.UTC())
	}
	if !q.To.IsZero() {
		db = db.Where("time <= ?", q.To.UTC())
	}
	if q.Severity != "" {
		db = db.Where("LOWER(severity) = LOWER(?)", q.Severity)
	}
	if len(q.Sources) > 0 {
		db = db.Where("LOWER(source) IN ?", lowerAll(q.Sources))
	}
	if q.Query != "" {
		like := "%" + strings.ToLower(q.Query) + "%"
		db = db.Where("LOWER(message) LIKE ? OR LOWER(source) LIKE ?", like, like)
	}

	var total int64
	if err := db.Count(&total).Error; err != nil {
		return web.SearchResult{}, fmt.Errorf("count events: %w", err)
	}

	limit := q.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 2000 {
		limit = 2000
	}

	order := "time ASC"
	if q.SortDesc {
		order = "time DESC"
	}

	var rows []Event
	if err := db.Order(order).Limit(limit).Find(&rows).Error; err != nil {
		return web.SearchResult{}, fmt.Errorf("find events: %w", err)
	}

	events := make([]web.Event, len(rows))
	for i, r := range rows {
		events[i] = web.Event{Time: r.Time, Source: r.Source, Severity: r.Severity, Message: r.Message}
	}
	return web.SearchResult{
		Events: events,
		Total:  int(total),
		TookMS: float64(time.Since(start).Microseconds()) / 1000,
	}, nil
}

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

func (s *Store) Close() error {
	sqlDB, err := s.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.Close()
}

func (s *Store) PruneBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	res := s.db.WithContext(ctx).Where("time < ?", cutoff.UTC()).Delete(&Event{})
	return res.RowsAffected, res.Error
}

func newGormLogger(level string) gormlogger.Interface {
	var lvl gormlogger.LogLevel
	switch level {
	case "silent":
		lvl = gormlogger.Silent
	case "error":
		lvl = gormlogger.Error
	case "info":
		lvl = gormlogger.Info
	default:
		lvl = gormlogger.Warn
	}
	return gormlogger.New(
		slogWriter{slog.Default()},
		gormlogger.Config{LogLevel: lvl, SlowThreshold: 200 * time.Millisecond},
	)
}

type slogWriter struct{ l *slog.Logger }

func (w slogWriter) Printf(format string, args ...any) {
	w.l.Info(fmt.Sprintf(format, args...))
}

// Open connects to the configured database and applies migrations.
func Open(cfg config.DBConfig) (*Store, error) {
	dialector, err := dialectorFor(cfg)
	if err != nil {
		return nil, err
	}

	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: newGormLogger(cfg.LogLevel),
	})
	if err != nil {
		return nil, fmt.Errorf("open database (%s): %w", cfg.Driver, err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("get sql.DB handle: %w", err)
	}
	sqlDB.SetMaxOpenConns(cfg.MaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	if err := migrate(db); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func dialectorFor(cfg config.DBConfig) (gorm.Dialector, error) {
	switch cfg.Driver {
	case "sqlite", "":
		if dir := filepath.Dir(cfg.DSN); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return nil, fmt.Errorf("create db dir %s: %w", dir, err)
			}
		}
		dsn := cfg.DSN
		if !strings.Contains(dsn, "?") {
			dsn += "?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=1"
		}
		return sqlite.Open(dsn), nil
	case "postgres":
		return postgres.Open(cfg.DSN), nil
	case "mysql":
		return mysql.Open(cfg.DSN), nil
	default:
		return nil, fmt.Errorf("unsupported driver %q", cfg.Driver)
	}
}

func containsQuery(dsn string) bool { return strings.Contains(dsn, "?") }

func migrate(db *gorm.DB) error {
	if err := db.AutoMigrate(&Event{}, &AuthUser{}, &AuthSession{}, &AlertRecord{}, &AlertNote{}, &AlertHistory{}); err != nil {
		return fmt.Errorf("auto migrate database: %w", err)
	}
	return nil
}

func (s *Store) LoadAuthState() ([]web.AuthUserRecord, []web.AuthSessionRecord, error) {
	var users []AuthUser
	if err := s.db.Order("username").Find(&users).Error; err != nil {
		return nil, nil, fmt.Errorf("load auth users: %w", err)
	}
	var sessions []AuthSession
	if err := s.db.Where("expires > ?", time.Now().UTC()).Find(&sessions).Error; err != nil {
		return nil, nil, fmt.Errorf("load auth sessions: %w", err)
	}
	outUsers := make([]web.AuthUserRecord, 0, len(users))
	for _, u := range users {
		outUsers = append(outUsers, web.AuthUserRecord{Username: u.Username, Role: u.Role, Salt: u.Salt, Hash: u.Hash})
	}
	outSessions := make([]web.AuthSessionRecord, 0, len(sessions))
	for _, v := range sessions {
		outSessions = append(outSessions, web.AuthSessionRecord{TokenHash: v.TokenHash, Username: v.Username, Role: v.Role, Expires: v.Expires})
	}
	return outUsers, outSessions, nil
}
func (s *Store) SaveAuthUser(u web.AuthUserRecord) error {
	row := AuthUser{Username: u.Username, Role: u.Role, Salt: u.Salt, Hash: u.Hash}
	if err := s.db.Where("username = ?", u.Username).Assign(row).FirstOrCreate(&row).Error; err != nil {
		return fmt.Errorf("save auth user: %w", err)
	}
	return nil
}
func (s *Store) SaveAuthSession(v web.AuthSessionRecord) error {
	row := AuthSession{TokenHash: v.TokenHash, Username: v.Username, Role: v.Role, Expires: v.Expires.UTC()}
	if err := s.db.Create(&row).Error; err != nil {
		return fmt.Errorf("save auth session: %w", err)
	}
	return nil
}
func (s *Store) DeleteAuthSession(tokenHash string) error {
	return s.db.Where("token_hash = ?", tokenHash).Delete(&AuthSession{}).Error
}
func (s *Store) DeleteAuthSessions(username string) error {
	return s.db.Where("username = ?", username).Delete(&AuthSession{}).Error
}

// HasAuthUsers reports whether bootstrap credentials are still required.
func (s *Store) HasAuthUsers() (bool, error) {
	var count int64
	if err := s.db.Model(&AuthUser{}).Count(&count).Error; err != nil {
		return false, fmt.Errorf("check auth users: %w", err)
	}
	return count > 0, nil
}
