package profile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type RuleHandler interface {
	Validate(raw []byte, format string) (id string, err error)
	Save(raw []byte, format string) error
	Delete(id string) error
}

type IntegrationHandler interface {
	Get(id string) (enabled, alerting bool, exists bool)
	Update(id string, enabled, alerting bool) error
	Apply(id string) error
}

type Manager struct {
	mu           sync.Mutex
	root         string
	rules        RuleHandler
	integrations IntegrationHandler
}

func NewManager(dataDir string, rules RuleHandler, integrations IntegrationHandler) (*Manager, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, errors.New("profile data directory is required")
	}
	if rules == nil || integrations == nil {
		return nil, errors.New("profile rule and integration handlers are required")
	}
	root := filepath.Join(dataDir, "profiles")
	for _, dir := range []string{root, filepath.Join(root, "installed"), filepath.Join(root, "uploads")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create %s: %w", dir, err)
		}
	}
	return &Manager{root: root, rules: rules, integrations: integrations}, nil
}

func (m *Manager) Validate(data []byte) (Preview, error) {
	b, err := ReadArchive(data)
	if err != nil {
		return Preview{}, err
	}
	return m.preview(b)
}

func (m *Manager) preview(b *Bundle) (Preview, error) {
	p := Preview{Manifest: b.Manifest}
	if len(b.Manifest.Spec.Requirements.Platform) > 0 {
		compatible := false
		for _, platform := range b.Manifest.Spec.Requirements.Platform {
			if strings.EqualFold(strings.TrimSpace(platform), runtime.GOOS) {
				compatible = true
				break
			}
		}
		if !compatible {
			return p, fmt.Errorf("profile is not compatible with platform %q", runtime.GOOS)
		}
	}
	seenRules := map[string]bool{}
	if b.Manifest.Spec.Rules.Enabled {
		for name, raw := range b.Files {
			if !under(name, b.Manifest.Spec.Rules.Path) || !isRuleFile(name) {
				continue
			}
			id, err := m.rules.Validate(raw, strings.TrimPrefix(strings.ToLower(path.Ext(name)), "."))
			if err != nil {
				return p, fmt.Errorf("rule %s: %w", name, err)
			}
			if seenRules[id] {
				return p, fmt.Errorf("duplicate rule id %q in profile", id)
			}
			seenRules[id] = true
			p.Rules = append(p.Rules, id)
		}
		if len(p.Rules) == 0 {
			return p, errors.New("rules are enabled but no YAML/JSON rule files were found")
		}
	}
	if b.Manifest.Spec.Integrations.Enabled {
		for name, raw := range b.Files {
			if !under(name, b.Manifest.Spec.Integrations.Path) || !isConfigFile(name) {
				continue
			}
			var item IntegrationConfig
			if err := yaml.Unmarshal(raw, &item); err != nil {
				return p, fmt.Errorf("integration %s: %w", name, err)
			}
			if item.ID == "" {
				return p, fmt.Errorf("integration %s: id is required", name)
			}
			if _, _, ok := m.integrations.Get(item.ID); !ok {
				return p, fmt.Errorf("integration %s: unknown built-in integration %q", name, item.ID)
			}
			for _, old := range p.Integrations {
				if old.ID == item.ID {
					return p, fmt.Errorf("duplicate integration %q", item.ID)
				}
			}
			p.Integrations = append(p.Integrations, item)
		}
	}
	for name := range b.Files {
		if under(name, b.Manifest.Spec.Config.Path) && isConfigFile(name) {
			if err := validateConfig(b.Files[name]); err != nil {
				return p, fmt.Errorf("config %s: %w", name, err)
			}
			p.ConfigFiles = append(p.ConfigFiles, name)
		}
	}
	sort.Strings(p.Rules)
	sort.Strings(p.ConfigFiles)
	sort.Slice(p.Integrations, func(i, j int) bool { return p.Integrations[i].ID < p.Integrations[j].ID })
	if len(p.ConfigFiles) > 0 {
		p.Warnings = append(p.Warnings, "Configuration files are stored with the profile; this version does not merge them into global application settings.")
	}
	return p, nil
}

func (m *Manager) Install(data []byte) (InstalledProfile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	b, err := ReadArchive(data)
	if err != nil {
		return InstalledProfile{}, err
	}
	preview, err := m.preview(b)
	if err != nil {
		return InstalledProfile{}, err
	}
	id := b.Manifest.Metadata.ID
	dest := filepath.Join(m.root, "installed", id)
	if _, err := os.Stat(dest); err == nil {
		return InstalledProfile{}, fmt.Errorf("profile %q is already installed; remove it before reinstalling", id)
	} else if !os.IsNotExist(err) {
		return InstalledProfile{}, err
	}

	record := InstalledProfile{Manifest: b.Manifest, InstalledAt: time.Now().UTC(), RuleIDs: append([]string(nil), preview.Rules...), Integrations: preview.Integrations, ConfigFiles: preview.ConfigFiles}
	rollbackRules := []string{}
	rollbackIntegrations := []PreviousIntegration{}
	rollback := func(cause error) (InstalledProfile, error) {
		for i := len(rollbackIntegrations) - 1; i >= 0; i-- {
			old := rollbackIntegrations[i]
			_ = m.integrations.Update(old.ID, old.Enabled, old.Alerting)
			_ = m.integrations.Apply(old.ID)
		}
		for i := len(rollbackRules) - 1; i >= 0; i-- {
			_ = m.rules.Delete(rollbackRules[i])
		}
		return InstalledProfile{}, cause
	}

	for name, raw := range b.Files {
		if !under(name, b.Manifest.Spec.Rules.Path) || !isRuleFile(name) || !b.Manifest.Spec.Rules.Enabled {
			continue
		}
		id, err := m.rules.Validate(raw, strings.TrimPrefix(strings.ToLower(path.Ext(name)), "."))
		if err != nil {
			return rollback(err)
		}
		if err = m.rules.Save(raw, strings.TrimPrefix(strings.ToLower(path.Ext(name)), ".")); err != nil {
			return rollback(fmt.Errorf("save rule %s: %w", name, err))
		}
		rollbackRules = append(rollbackRules, id)
	}
	if b.Manifest.Spec.Integrations.Enabled && b.Manifest.Spec.Integrations.AutoEnable {
		for _, item := range preview.Integrations {
			enabled, alerting, ok := m.integrations.Get(item.ID)
			if !ok {
				return rollback(fmt.Errorf("integration %q disappeared during install", item.ID))
			}
			rollbackIntegrations = append(rollbackIntegrations, PreviousIntegration{ID: item.ID, Enabled: enabled, Alerting: alerting})
			record.Previous = append(record.Previous, rollbackIntegrations[len(rollbackIntegrations)-1])
			nextAlerting := alerting
			if item.Alerting != nil {
				nextAlerting = *item.Alerting
			}
			if err := m.integrations.Update(item.ID, item.Enabled, nextAlerting); err != nil {
				return rollback(err)
			}
			if err := m.integrations.Apply(item.ID); err != nil {
				return rollback(fmt.Errorf("apply integration %s: %w", item.ID, err))
			}
		}
	}

	stage, err := os.MkdirTemp(filepath.Join(m.root, "installed"), ".profile-stage-")
	if err != nil {
		return rollback(err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(stage)
		}
	}()
	for name, raw := range b.Files {
		if name == "manifest.yaml" || name == "manifest.yml" || strings.HasPrefix(name, "rules/") || strings.HasPrefix(name, "integrations/") || strings.HasPrefix(name, "config/") || name == "README.md" {
			target := filepath.Join(stage, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return rollback(err)
			}
			if err := os.WriteFile(target, raw, 0o600); err != nil {
				return rollback(err)
			}
		}
	}
	meta, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return rollback(err)
	}
	if err = os.WriteFile(filepath.Join(stage, "installed.json"), meta, 0o600); err != nil {
		return rollback(err)
	}
	if err = os.Rename(stage, dest); err != nil {
		return rollback(err)
	}
	cleanup = false
	return record, nil
}

func (m *Manager) List() ([]InstalledProfile, error) {
	entries, err := os.ReadDir(filepath.Join(m.root, "installed"))
	if err != nil {
		return nil, err
	}
	out := []InstalledProfile{}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(m.root, "installed", e.Name(), "installed.json"))
		if err != nil {
			return nil, err
		}
		var p InstalledProfile
		if err = json.Unmarshal(b, &p); err != nil {
			return nil, fmt.Errorf("read installed profile %s: %w", e.Name(), err)
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Manifest.Metadata.ID < out[j].Manifest.Metadata.ID })
	return out, nil
}

func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !profileIDRE.MatchString(id) {
		return errors.New("invalid profile id")
	}
	dir := filepath.Join(m.root, "installed", id)
	b, err := os.ReadFile(filepath.Join(dir, "installed.json"))
	if err != nil {
		return err
	}
	var p InstalledProfile
	if err = json.Unmarshal(b, &p); err != nil {
		return err
	}
	// Restore an integration only if it still has the value this profile applied.
	for _, old := range p.Previous {
		for _, cur := range p.Integrations {
			if cur.ID != old.ID {
				continue
			}
			enabled, alerting, ok := m.integrations.Get(old.ID)
			if !ok {
				continue
			}
			expectedAlert := old.Alerting
			if cur.Alerting != nil {
				expectedAlert = *cur.Alerting
			}
			if enabled == cur.Enabled && alerting == expectedAlert {
				if err := m.integrations.Update(old.ID, old.Enabled, old.Alerting); err != nil {
					return err
				}
				if err := m.integrations.Apply(old.ID); err != nil {
					return err
				}
			}
		}
	}
	for _, ruleID := range p.RuleIDs {
		if err := m.rules.Delete(ruleID); err != nil {
			return fmt.Errorf("delete owned rule %s: %w", ruleID, err)
		}
	}
	return os.RemoveAll(dir)
}

func under(name, dir string) bool {
	dir = strings.TrimSuffix(dir, "/")
	return dir != "" && strings.HasPrefix(name, dir+"/")
}
func isRuleFile(name string) bool {
	e := strings.ToLower(path.Ext(name))
	return e == ".yaml" || e == ".yml" || e == ".json"
}
func isConfigFile(name string) bool { return isRuleFile(name) }

func validateConfig(raw []byte) error {
	var v any
	if err := yaml.Unmarshal(raw, &v); err != nil {
		return err
	}
	var walk func(any) error
	walk = func(x any) error {
		switch t := x.(type) {
		case map[string]any:
			for k, v := range t {
				l := strings.ToLower(strings.ReplaceAll(k, "-", "_"))
				for _, bad := range []string{"password", "secret", "token", "private_key", "api_key", "credential"} {
					if strings.Contains(l, bad) {
						return fmt.Errorf("secret-like key %q is not allowed in profile config", k)
					}
				}
				if err := walk(v); err != nil {
					return err
				}
			}
		case map[any]any:
			for k, v := range t {
				if err := walk(fmt.Sprint(k)); err != nil {
					return err
				}
				if err := walk(v); err != nil {
					return err
				}
			}
		case []any:
			for _, v := range t {
				if err := walk(v); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(v)
}

func Platform() string { return runtime.GOOS }
