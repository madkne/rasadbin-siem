package web

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
	"rasadbin/internal/detection"
)

const (
	authDeadline = 10 * time.Second
	writeTimeout = 10 * time.Second
	pingInterval = 30 * time.Second
	readLimit    = 64 << 10
)

type envelope struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

type client struct {
	srv        *Server
	conn       *websocket.Conn
	ip         string
	send       chan []byte
	cancel     context.CancelFunc
	subscribed atomic.Bool

	mu    sync.RWMutex
	token string
	sess  *Session
}

func (s *Server) serveWS(w http.ResponseWriter, r *http.Request) {
	// Accept rejects cross-origin handshakes (Origin must match Host).
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	conn.SetReadLimit(readLimit)
	if s.baseCtx == nil {
		s.baseCtx = context.Background()
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	c := &client{
		srv:    s,
		conn:   conn,
		ip:     clientIP(r),
		send:   make(chan []byte, 32),
		cancel: cancel,
	}
	s.hub.add(c)
	defer s.hub.remove(c)

	// Unauthenticated sockets get a few seconds, then are dropped.
	timer := time.AfterFunc(authDeadline, func() {
		if _, sess := c.identity(); sess == nil {
			cancel()
		}
	})
	defer timer.Stop()

	go c.writeLoop(ctx)
	c.readLoop(ctx)
	_ = conn.CloseNow()
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (c *client) readLoop(ctx context.Context) {
	for {
		typ, data, err := c.conn.Read(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageText {
			continue
		}
		var env envelope
		if err := json.Unmarshal(data, &env); err != nil {
			c.sendError("", "malformed message")
			continue
		}
		c.dispatch(env)
	}
}

func (c *client) writeLoop(ctx context.Context) {
	ping := time.NewTicker(pingInterval)
	defer ping.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case b := <-c.send:
			wctx, cancel := context.WithTimeout(ctx, writeTimeout)
			err := c.conn.Write(wctx, websocket.MessageText, b)
			cancel()
			if err != nil {
				c.cancel()
				return
			}
		case <-ping.C:
			pctx, cancel := context.WithTimeout(ctx, writeTimeout)
			err := c.conn.Ping(pctx)
			cancel()
			if err != nil {
				c.cancel()
				return
			}
		}
	}
}

// enqueue never blocks; a client that cannot keep up is disconnected.
func (c *client) enqueue(b []byte) {
	select {
	case c.send <- b:
	default:
		c.cancel()
	}
}

func (c *client) sendJSON(typ string, data any) { c.enqueue(encode(typ, data)) }

func (c *client) sendError(forType, msg string) {
	c.sendJSON("error", errorData{For: forType, Message: msg})
}

func (c *client) identity() (string, *Session) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.token, c.sess
}

func (c *client) setIdentity(token string, s *Session) {
	c.mu.Lock()
	c.token, c.sess = token, s
	c.mu.Unlock()
}

// current re-validates the session on every use. A dead session is cleared
// and the client is told to sign in again.
func (c *client) current() *Session {
	token, _ := c.identity()
	if token == "" {
		return nil
	}
	if s, ok := c.srv.auth.Validate(token); ok {
		return s
	}
	c.setIdentity("", nil)
	c.subscribed.Store(false)
	c.sendJSON("session_expired", nil)
	time.AfterFunc(time.Second, c.cancel)
	return nil
}

func (c *client) dispatch(env envelope) {
	switch env.Type {
	case "login":
		c.handleLogin(env.Data)
		return
	case "auth":
		c.handleAuth(env.Data)
		return
	}

	sess := c.current()
	if sess == nil {
		c.sendError(env.Type, "not authenticated")
		return
	}

	switch env.Type {
	case "logout":
		token, _ := c.identity()
		c.srv.auth.Logout(token)
		c.setIdentity("", nil)
		c.subscribed.Store(false)
		c.sendJSON("logged_out", nil)

	case "subscribe":
		c.subscribed.Store(true)
		c.sendJSON("dashboard", map[string]any{
			"stats":  c.srv.hub.Snapshot(),
			"events": c.srv.hub.Recent(),
		})

	case "unsubscribe":
		c.subscribed.Store(false)

	case "integrations.get":
		if c.requireAdmin(env.Type, sess) {
			c.sendJSON("integrations", c.srv.Integrations())
		}
	case "alerts.get":
		c.sendJSON("alerts", c.srv.RecentAlerts(500))

	case "match_terms.get", "match_terms", "rules.match_terms", "rule.match_terms", "rules.terms", "rule.terms", "terms.get":
		if c.requireAdmin(env.Type, sess) {
			if c.srv.detection == nil {
				c.sendError(env.Type, "detection engine is unavailable")
				break
			}
			terms := c.srv.detection.MatchTerms()
			c.sendJSON("match_terms", terms)
		}
	case "rules.get":
		if c.requireAdmin(env.Type, sess) {
			if c.srv.detection == nil {
				c.sendError(env.Type, "detection engine is unavailable")
				break
			}
			c.sendJSON("rules", c.srv.detection.Rules())
		}
	case "rule.validate":
		if c.requireAdmin(env.Type, sess) {
			c.handleRuleValidate(env.Data)
		}
	case "rule.save":
		if c.requireAdmin(env.Type, sess) {
			c.handleRuleSave(env.Data, sess)
		}
	case "rule.delete":
		if c.requireAdmin(env.Type, sess) {
			c.handleRuleDelete(env.Data, sess)
		}

	case "integration.update":
		if c.requireAdmin(env.Type, sess) {
			c.handleIntegrationUpdate(env.Data, sess)
		}
	case "discover.search":
		var q SearchQuery
		if err := decodeStrict(env.Data, &q); err != nil {
			c.sendError(env.Type, "invalid search query")
			break
		}
		if c.srv.store != nil {
			res, err := c.srv.store.Query(c.srv.baseCtx, q)
			if err != nil {
				slog.Error("discover query", "error", err)
				c.sendError(env.Type, "query failed")
				break
			}
			c.sendJSON("discover.results", res)
		} else {
			c.sendJSON("discover.results", c.srv.hub.Search(q))
		}

	case "discover.sources":
		// Distinct source IDs present in the retained buffer, for filter chips.
		seen := map[string]struct{}{}
		for _, e := range c.srv.hub.Recent() {
			seen[e.Source] = struct{}{}
		}
		sources := make([]string, 0, len(seen))
		for s := range seen {
			sources = append(sources, s)
		}
		sort.Strings(sources)
		c.sendJSON("discover.sources", sources)
	case "integration.events":
		var req struct {
			ID string `json:"id"`
		}
		if err := decodeStrict(env.Data, &req); err != nil {
			c.sendError(env.Type, "invalid integration id")
			break
		}
		if _, ok := c.srv.integrations.Get(req.ID); !ok {
			c.sendError(env.Type, "unknown integration")
			break
		}
		events := c.srv.hub.Recent()
		filtered := make([]Event, 0)
		for _, e := range events {
			if e.Source == req.ID {
				filtered = append(filtered, e)
			}
		}
		c.sendJSON("integration.events", map[string]any{"id": req.ID, "events": filtered})

	case "settings.get":
		if c.requireAdmin(env.Type, sess) {
			c.sendJSON("settings", c.srv.settings.Get())
		}

	case "settings.update":
		if c.requireAdmin(env.Type, sess) {
			c.handleSettingsUpdate(env.Data, sess)
		}

	case "password.change":
		c.handlePasswordChange(env.Data, sess)

	default:
		c.sendError(env.Type, "unknown message type")
	}
}

func (c *client) requireAdmin(typ string, s *Session) bool {
	if s.Role != "admin" {
		c.sendError(typ, "admin access required")
		return false
	}
	return true
}

func (c *client) handleLogin(raw json.RawMessage) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeStrict(raw, &req); err != nil ||
		req.Username == "" || req.Password == "" ||
		len(req.Username) > 128 || len(req.Password) > maxPasswordLen {
		c.sendJSON("login_failed", errorData{For: "login", Message: "Invalid username or password."})
		return
	}

	token, sess, err := c.srv.auth.Login(req.Username, req.Password, c.ip)
	switch {
	case errors.Is(err, ErrTooManyAttempts):
		slog.Warn("login blocked", "ip", c.ip)
		c.sendJSON("login_failed", errorData{For: "login", Message: "Too many failed attempts. Try again in a few minutes."})
		return
	case err != nil:
		slog.Warn("login failed", "user", req.Username, "ip", c.ip)
		c.sendJSON("login_failed", errorData{For: "login", Message: "Invalid username or password."})
		return
	}

	c.setIdentity(token, &sess)
	slog.Info("audit", "action", "login", "user", sess.Username, "ip", c.ip)
	c.sendJSON("login_ok", map[string]any{
		"token":      token,
		"username":   sess.Username,
		"role":       sess.Role,
		"expires_at": sess.Expires,
	})
}

func (c *client) handleAuth(raw json.RawMessage) {
	var req struct {
		Token string `json:"token"`
	}
	if err := decodeStrict(raw, &req); err != nil {
		c.sendJSON("auth_failed", nil)
		return
	}
	sess, ok := c.srv.auth.Validate(req.Token)
	if !ok {
		c.sendJSON("auth_failed", nil)
		return
	}
	c.setIdentity(req.Token, sess)
	c.sendJSON("auth_ok", map[string]any{
		"username":      sess.Username,
		"role":          sess.Role,
		"expires_at":    sess.Expires,
		"instance_name": c.srv.settings.Get().InstanceName,
	})
}

func (c *client) handleSettingsUpdate(raw json.RawMessage, sess *Session) {
	var next Settings
	if err := decodeStrict(raw, &next); err != nil {
		c.sendError("settings.update", "invalid settings payload")
		return
	}
	if err := next.Validate(); err != nil {
		c.sendError("settings.update", err.Error())
		return
	}
	if err := c.srv.settings.Update(next); err != nil {
		slog.Error("saving settings failed", "error", err)
		c.sendError("settings.update", "could not save settings")
		return
	}
	slog.Info("audit", "action", "settings.update", "user", sess.Username, "ip", c.ip)
	c.sendJSON("settings_saved", next)
}

func (c *client) handlePasswordChange(raw json.RawMessage, sess *Session) {
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := decodeStrict(raw, &req); err != nil ||
		len(req.Current) > maxPasswordLen || len(req.New) > maxPasswordLen {
		c.sendError("password.change", "invalid request")
		return
	}

	switch err := c.srv.auth.ChangePassword(sess.Username, req.Current, req.New); {
	case errors.Is(err, ErrInvalidCredentials):
		c.sendError("password.change", "current password is incorrect")
	case errors.Is(err, ErrTooManyAttempts):
		c.sendError("password.change", "too many failed attempts, try again later")
	case errors.Is(err, ErrWeakPassword):
		c.sendError("password.change", err.Error())
	case err != nil:
		slog.Error("password change failed", "error", err)
		c.sendError("password.change", "could not change password")
	default:
		slog.Info("audit", "action", "password.change", "user", sess.Username, "ip", c.ip)
		c.setIdentity("", nil) // all sessions were revoked
		c.subscribed.Store(false)
		c.sendJSON("password_changed", nil)
	}
}

func (c *client) handleIntegrationUpdate(raw json.RawMessage, sess *Session) {
	var req struct {
		ID       string `json:"id"`
		Enabled  bool   `json:"enabled"`
		Alerting bool   `json:"alerting"`
	}
	if err := decodeStrict(raw, &req); err != nil || req.ID == "" {
		c.sendError("integration.update", "invalid integration payload")
		return
	}
	item, err := c.srv.integrations.Update(
		req.ID,
		req.Enabled,
		req.Alerting,
	)
	if err != nil {
		c.sendError("integration.update", err.Error())
		return
	}

	if c.srv.collectorManager != nil {
		if err := c.srv.collectorManager.Apply(req.ID); err != nil {
			// The manager has recorded the failure status.
			// Return the latest integration so the UI can display it.
			if latest, ok := c.srv.integrations.Get(req.ID); ok {
				item = latest
			}
			slog.Error("integration collector update failed",
				"integration", req.ID,
				"error", err)
		}
	}

	if latest, ok := c.srv.integrations.Get(req.ID); ok {
		item = latest
	}

	slog.Info("audit",
		"action", "integration.update",
		"integration", req.ID,
		"enabled", req.Enabled,
		"user", sess.Username,
		"ip", c.ip)

	c.srv.hub.Broadcast("integration_saved", item)
}

func (c *client) handleRuleValidate(raw json.RawMessage) {
	var rule detection.Rule
	if err := decodeStrict(raw, &rule); err != nil {
		c.sendError("rule.validate", "invalid rule payload")
		return
	}
	if err := detection.ValidateRule(rule); err != nil {
		c.sendJSON("rule.validated", map[string]any{"valid": false, "message": err.Error()})
		return
	}
	c.sendJSON("rule.validated", map[string]any{"valid": true, "message": "Rule is valid."})
}

func (c *client) handleRuleSave(raw json.RawMessage, sess *Session) {
	var rule detection.Rule
	if err := decodeStrict(raw, &rule); err != nil {
		c.sendError("rule.save", "invalid rule payload")
		return
	}
	if c.srv.detection == nil {
		c.sendError("rule.save", "detection engine is unavailable")
		return
	}
	if err := c.srv.detection.SaveRule(rule); err != nil {
		c.sendError("rule.save", err.Error())
		return
	}
	slog.Info("audit", "action", "rule.save", "rule", rule.ID, "user", sess.Username, "ip", c.ip)
	c.sendJSON("rule.saved", map[string]any{"rule": rule, "rules": c.srv.detection.Rules()})
}

func (c *client) handleRuleDelete(raw json.RawMessage, sess *Session) {
	var req struct {
		ID string `json:"id"`
	}
	if err := decodeStrict(raw, &req); err != nil || req.ID == "" {
		c.sendError("rule.delete", "invalid rule id")
		return
	}
	if c.srv.detection == nil {
		c.sendError("rule.delete", "detection engine is unavailable")
		return
	}
	if err := c.srv.detection.DeleteRule(req.ID); err != nil {
		c.sendError("rule.delete", err.Error())
		return
	}
	slog.Info("audit", "action", "rule.delete", "rule", req.ID, "user", sess.Username, "ip", c.ip)
	c.sendJSON("rule.deleted", map[string]any{"id": req.ID, "rules": c.srv.detection.Rules()})
}
