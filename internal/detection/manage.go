package detection

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var ruleIDPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,99}$`)

func (e *Engine) MatchTerms() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	seen := map[string]struct{}{}
	add := func(t string) {
		t = strings.TrimSpace(t)
		if t == "" {
			return
		}
		seen[t] = struct{}{}
	}
	for _, t := range []string{
		"Failed password",
		"authentication failure",
		"authentication failed",
		"auth failure",
		"failed login",
		"login failed",
		"Invalid user",
		"invalid user",
		"pam_unix",
	} {
		add(t)
	}
	for _, r := range e.rules {
		for _, t := range r.MatchAny {
			add(t)
		}
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
func (e *Engine) Rules() []Rule {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Rule, len(e.rules))
	copy(out, e.rules)
	for i := range out {
		out[i].Sources = append([]string(nil), out[i].Sources...)
		out[i].MatchAny = append([]string(nil), out[i].MatchAny...)
		if out[i].Enabled != nil {
			v := *out[i].Enabled
			out[i].Enabled = &v
		}
	}
	return out
}

func ValidateRule(rule Rule) error {
	if !ruleIDPattern.MatchString(strings.TrimSpace(rule.ID)) {
		return errors.New("id must start with a letter or number and contain only letters, numbers, dot, underscore or hyphen")
	}
	dir, err := os.MkdirTemp("", "rasadbin-rules-validate-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	b, err := json.Marshal(rule)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, rule.ID+".json"), b, 0600); err != nil {
		return err
	}
	_, err = New(dir)
	return err
}

// findRuleFile locates a rule stored alone in a YAML/JSON file. Rule arrays are
// deliberately not edited by the UI, to avoid accidentally deleting siblings.
func findRuleFile(dir, id string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(ent.Name()))
		if ext != ".yaml" && ext != ".yml" && ext != ".json" {
			continue
		}
		path := filepath.Join(dir, ent.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		var one Rule
		if yaml.Unmarshal(b, &one) == nil && one.ID == id {
			return path, nil
		}
		var many []Rule
		if yaml.Unmarshal(b, &many) == nil {
			for _, r := range many {
				if r.ID == id {
					return "", fmt.Errorf("rule %q is inside a rule array; split it into a separate file before editing", id)
				}
			}
		}
	}
	return "", fs.ErrNotExist
}

// SaveRule validates the complete candidate rule set before atomically replacing
// a rule file, then reloads the live engine. Existing single-rule YAML files can
// be edited from the UI; new rules are saved as <id>.json.
func (e *Engine) SaveRule(rule Rule) error {
	if e == nil {
		return errors.New("detection engine is unavailable")
	}
	if !ruleIDPattern.MatchString(strings.TrimSpace(rule.ID)) {
		return errors.New("invalid rule id")
	}
	e.mu.Lock()
	dir := e.rulesDir
	current := append([]Rule(nil), e.rules...)
	e.mu.Unlock()
	if dir == "" {
		return errors.New("rules directory is not configured")
	}
	candidate := make([]Rule, 0, len(current)+1)
	for _, old := range current {
		if old.ID != rule.ID {
			candidate = append(candidate, old)
		}
	}
	candidate = append(candidate, rule)
	tmp, err := os.MkdirTemp("", "rasadbin-rules-check-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	for _, r := range candidate {
		b, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(tmp, r.ID+".json"), b, 0600); err != nil {
			return err
		}
	}
	if _, err := New(tmp); err != nil {
		return err
	}
	path, locateErr := findRuleFile(dir, rule.ID)
	if locateErr != nil && !errors.Is(locateErr, fs.ErrNotExist) {
		return locateErr
	}
	if errors.Is(locateErr, fs.ErrNotExist) {
		path = filepath.Join(dir, rule.ID+".json")
	}
	previous, readErr := os.ReadFile(path)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	b, err := json.MarshalIndent(rule, "", "  ")
	if err != nil {
		return err
	}
	stage, err := os.CreateTemp(dir, ".rule-*.tmp")
	if err != nil {
		return err
	}
	stageName := stage.Name()
	if _, err = stage.Write(append(b, '\n')); err == nil {
		err = stage.Sync()
	}
	closeErr := stage.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(stageName)
		return err
	}
	if err := os.Rename(stageName, path); err != nil {
		_ = os.Remove(stageName)
		return err
	}
	if err := e.Reload(dir); err != nil {
		if readErr == nil {
			_ = os.WriteFile(path, previous, 0600)
		} else {
			_ = os.Remove(path)
		}
		_ = e.Reload(dir)
		return fmt.Errorf("reload rules: %w", err)
	}
	return nil
}

func (e *Engine) DeleteRule(id string) error {
	if e == nil {
		return errors.New("detection engine is unavailable")
	}
	if !ruleIDPattern.MatchString(strings.TrimSpace(id)) {
		return errors.New("invalid rule id")
	}
	e.mu.Lock()
	dir := e.rulesDir
	exists := false
	for _, r := range e.rules {
		if r.ID == id {
			exists = true
			break
		}
	}
	e.mu.Unlock()
	if !exists {
		return os.ErrNotExist
	}
	path, err := findRuleFile(dir, id)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil {
		return err
	}
	if err := e.Reload(dir); err != nil {
		_ = os.WriteFile(path, b, 0600)
		_ = e.Reload(dir)
		return err
	}
	return nil
}
