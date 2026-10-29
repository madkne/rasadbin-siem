package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode/utf8"
)

// Settings are the values editable from the admin settings page.
type Settings struct {
	InstanceName   string `json:"instance_name"`
	LogLevel       string `json:"log_level"`       // debug | info | warn | error
	SessionMinutes int    `json:"session_minutes"` // 5..1440
	RetentionDays  int    `json:"retention_days"`  // 1..3650 (not enforced yet)
	RefreshSeconds int    `json:"refresh_seconds"` // 1..60 dashboard push interval
}

func DefaultSettings() Settings {
	return Settings{
		InstanceName:   "Rasadbin",
		LogLevel:       "info",
		SessionMinutes: 60,
		RetentionDays:  30,
		RefreshSeconds: 2,
	}
}

func (s Settings) Validate() error {
	if n := utf8.RuneCountInString(strings.TrimSpace(s.InstanceName)); n < 1 || n > 64 {
		return errors.New("instance name must be 1-64 characters")
	}
	switch s.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return errors.New("log level must be debug, info, warn or error")
	}
	if s.SessionMinutes < 5 || s.SessionMinutes > 1440 {
		return errors.New("session timeout must be 5-1440 minutes")
	}
	if s.RetentionDays < 1 || s.RetentionDays > 3650 {
		return errors.New("retention must be 1-3650 days")
	}
	if s.RefreshSeconds < 1 || s.RefreshSeconds > 60 {
		return errors.New("dashboard refresh must be 1-60 seconds")
	}
	return nil
}

// SettingsStore keeps settings in memory and persists them as JSON.
type SettingsStore struct {
	mu       sync.RWMutex
	cur      Settings
	path     string
	onChange func(Settings)
}

func LoadSettings(path string, onChange func(Settings)) (*SettingsStore, error) {
	st := &SettingsStore{path: path, cur: DefaultSettings(), onChange: onChange}

	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &st.cur); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		if err := st.cur.Validate(); err != nil {
			return nil, fmt.Errorf("invalid %s: %w", path, err)
		}
	case errors.Is(err, os.ErrNotExist):
		// first run: defaults
	default:
		return nil, err
	}

	if onChange != nil {
		onChange(st.cur)
	}
	return st, nil
}

func (st *SettingsStore) Get() Settings {
	st.mu.RLock()
	defer st.mu.RUnlock()
	return st.cur
}

// Update validates, persists atomically and applies new settings.
func (st *SettingsStore) Update(next Settings) error {
	if err := next.Validate(); err != nil {
		return err
	}

	st.mu.Lock()
	defer st.mu.Unlock()

	b, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(st.path), 0o700); err != nil {
		return err
	}
	tmp := st.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, st.path); err != nil {
		return err
	}

	st.cur = next
	if st.onChange != nil {
		st.onChange(next)
	}
	return nil
}

func decodeStrict(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	// Reject trailing data — otherwise "strict" can be bypassed.
	if dec.More() {
		return errors.New("unexpected trailing data after JSON value")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return errors.New("unexpected trailing data after JSON value")
	}
	return nil
}
