package web

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"gopkg.in/yaml.v3"
	"rasadbin/internal/detection"
	"rasadbin/internal/profile"
)

const maxProfilePayload = 27 << 20

type profileRuleHandler struct{ engine *detection.Engine }

func (h profileRuleHandler) decode(raw []byte, format string) (detection.Rule, error) {
	var r detection.Rule
	if err := yaml.Unmarshal(raw, &r); err != nil {
		return r, err
	}
	if err := detection.ValidateRule(r); err != nil {
		return r, err
	}
	for _, old := range h.engine.Rules() {
		if old.ID == r.ID {
			return r, fmt.Errorf("rule id %q already exists", r.ID)
		}
	}
	return r, nil
}
func (h profileRuleHandler) Validate(raw []byte, format string) (string, error) {
	r, err := h.decode(raw, format)
	return r.ID, err
}
func (h profileRuleHandler) Save(raw []byte, format string) error {
	r, err := h.decode(raw, format)
	if err != nil {
		return err
	}
	return h.engine.SaveRule(r)
}
func (h profileRuleHandler) Delete(id string) error { return h.engine.DeleteRule(id) }

type profileIntegrationHandler struct {
	store      *IntegrationStore
	collectors *CollectorManager
}

func (h profileIntegrationHandler) Get(id string) (bool, bool, bool) {
	v, ok := h.store.Get(id)
	return v.Enabled, v.Alerting, ok
}
func (h profileIntegrationHandler) Update(id string, enabled, alerting bool) error {
	_, err := h.store.Update(id, enabled, alerting)
	return err
}
func (h profileIntegrationHandler) Apply(id string) error {
	if h.collectors == nil {
		return nil
	}
	return h.collectors.Apply(id)
}
func newProfileManager(dataDir string, engine *detection.Engine, store *IntegrationStore, collectors *CollectorManager) (*profile.Manager, error) {
	if engine == nil || store == nil {
		return nil, fmt.Errorf("profile dependencies unavailable")
	}
	return profile.NewManager(dataDir, profileRuleHandler{engine}, profileIntegrationHandler{store, collectors})
}

func (c *client) profileZIP(raw json.RawMessage) ([]byte, error) {
	var req struct {
		ZIP string `json:"zip"`
	}
	if len(raw) > maxProfilePayload {
		return nil, fmt.Errorf("profile payload is too large")
	}
	if err := decodeStrict(raw, &req); err != nil {
		return nil, fmt.Errorf("invalid profile payload")
	}
	if strings.TrimSpace(req.ZIP) == "" {
		return nil, fmt.Errorf("zip is required")
	}
	b, err := base64.StdEncoding.DecodeString(req.ZIP)
	if err != nil {
		return nil, fmt.Errorf("zip must be base64 encoded")
	}
	if len(b) > profile.MaxArchiveBytes {
		return nil, fmt.Errorf("ZIP exceeds maximum size")
	}
	return b, nil
}
func (c *client) handleProfileValidate(raw json.RawMessage) {
	if c.srv.profiles == nil {
		c.sendError("profile.validate", "profile manager is unavailable")
		return
	}
	b, err := c.profileZIP(raw)
	if err != nil {
		c.sendError("profile.validate", err.Error())
		return
	}
	preview, err := c.srv.profiles.Validate(b)
	if err != nil {
		c.sendError("profile.validate", err.Error())
		return
	}
	c.sendJSON("profile.validated", preview)
}
func (c *client) handleProfileInstall(raw json.RawMessage, sess *Session) {
	if c.srv.profiles == nil {
		c.sendError("profile.install", "profile manager is unavailable")
		return
	}
	b, err := c.profileZIP(raw)
	if err != nil {
		c.sendError("profile.install", err.Error())
		return
	}
	installed, err := c.srv.profiles.Install(b)
	if err != nil {
		c.sendError("profile.install", err.Error())
		return
	}
	slog.Info("audit", "action", "profile.install", "profile", installed.Manifest.Metadata.ID, "user", sess.Username, "ip", c.ip)
	c.sendJSON("profile.installed", map[string]any{"profile": installed})
	c.srv.hub.Broadcast("integrations", c.srv.Integrations())
}
func (c *client) handleProfileDelete(raw json.RawMessage, sess *Session) {
	if c.srv.profiles == nil {
		c.sendError("profile.delete", "profile manager is unavailable")
		return
	}
	var req struct {
		ID string `json:"id"`
	}
	if err := decodeStrict(raw, &req); err != nil || req.ID == "" {
		c.sendError("profile.delete", "invalid profile id")
		return
	}
	if err := c.srv.profiles.Delete(req.ID); err != nil {
		c.sendError("profile.delete", err.Error())
		return
	}
	slog.Info("audit", "action", "profile.delete", "profile", req.ID, "user", sess.Username, "ip", c.ip)
	items, err := c.srv.profiles.List()
	if err != nil {
		c.sendError("profile.delete", err.Error())
		return
	}
	c.sendJSON("profile.deleted", map[string]any{"id": req.ID, "profiles": items})
	c.srv.hub.Broadcast("integrations", c.srv.Integrations())
}

var _ profile.RuleHandler = profileRuleHandler{}
var _ profile.IntegrationHandler = profileIntegrationHandler{}
