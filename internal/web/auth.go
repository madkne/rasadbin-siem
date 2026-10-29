package web

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

const (
	pbkdf2Iterations = 600_000
	maxFailures      = 5
	lockoutWindow    = 5 * time.Minute
	minPasswordLen   = 10
	maxPasswordLen   = 128
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTooManyAttempts    = errors.New("too many failed attempts")
	ErrWeakPassword       = errors.New("new password must be 10-128 characters")
)

// user is immutable; changing a password replaces the map entry.
type user struct {
	name string
	role string
	salt []byte
	hash []byte
}

// Session is an authenticated login.
type Session struct {
	Username string
	Role     string
	Expires  time.Time
}

type failure struct {
	count int
	first time.Time
}

// Auth holds users, sessions and brute-force counters. Users and sessions
// are in memory only until the storage layer exists.
type Auth struct {
	mu       sync.Mutex
	users    map[string]*user
	sessions map[[32]byte]*Session
	failures map[string]*failure
	ttl      func() time.Duration
	dummy    *user // hashed against for unknown usernames (constant-ish timing)
}

// NewAuth creates the store with a single "admin" user.
func NewAuth(adminPassword string, ttl func() time.Duration) (*Auth, error) {
	admin, err := newUser("admin", "admin", adminPassword)
	if err != nil {
		return nil, err
	}
	dummy, err := newUser("", "", randomToken())
	if err != nil {
		return nil, err
	}
	return &Auth{
		users:    map[string]*user{"admin": admin},
		sessions: make(map[[32]byte]*Session),
		failures: make(map[string]*failure),
		ttl:      ttl,
		dummy:    dummy,
	}, nil
}

func newUser(name, role, password string) (*user, error) {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	hash, err := derive(password, salt)
	if err != nil {
		return nil, err
	}
	return &user{name: name, role: role, salt: salt, hash: hash}, nil
}

func derive(password string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, password, salt, pbkdf2Iterations, 32)
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(t string) [32]byte { return sha256.Sum256([]byte(t)) }

// Login verifies credentials and returns a new session token.
func (a *Auth) Login(username, password, ip string) (string, Session, error) {
	if a.locked(ip) {
		return "", Session{}, ErrTooManyAttempts
	}

	a.mu.Lock()
	u := a.users[username]
	a.mu.Unlock()

	target := a.dummy
	if u != nil {
		target = u
	}
	got, err := derive(password, target.salt)
	if err != nil {
		return "", Session{}, err
	}
	if subtle.ConstantTimeCompare(got, target.hash) != 1 || u == nil {
		a.recordFailure(ip)
		return "", Session{}, ErrInvalidCredentials
	}
	a.clearFailures(ip)

	token := randomToken()
	s := &Session{Username: u.name, Role: u.role, Expires: time.Now().Add(a.ttl())}
	a.mu.Lock()
	a.sessions[hashToken(token)] = s
	a.mu.Unlock()
	return token, *s, nil
}

// Validate returns a copy of the session for token, if it is still valid.
func (a *Auth) Validate(token string) (*Session, bool) {
	if token == "" {
		return nil, false
	}
	key := hashToken(token)
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(s.Expires) {
		delete(a.sessions, key)
		return nil, false
	}
	cp := *s
	return &cp, true
}

// Logout revokes a session token.
func (a *Auth) Logout(token string) {
	a.mu.Lock()
	delete(a.sessions, hashToken(token))
	a.mu.Unlock()
}

// ChangePassword verifies the current password, sets the new one and
// revokes every session of that user.
func (a *Auth) ChangePassword(username, current, next string) error {
	key := "pw:" + username
	if a.locked(key) {
		return ErrTooManyAttempts
	}

	a.mu.Lock()
	u := a.users[username]
	a.mu.Unlock()
	if u == nil {
		return ErrInvalidCredentials
	}

	got, err := derive(current, u.salt)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(got, u.hash) != 1 {
		a.recordFailure(key)
		return ErrInvalidCredentials
	}
	a.clearFailures(key)

	if len(next) < minPasswordLen || len(next) > maxPasswordLen {
		return ErrWeakPassword
	}
	nu, err := newUser(u.name, u.role, next)
	if err != nil {
		return err
	}

	a.mu.Lock()
	a.users[username] = nu
	for k, s := range a.sessions {
		if s.Username == username {
			delete(a.sessions, k)
		}
	}
	a.mu.Unlock()
	return nil
}

// Sweep drops expired sessions and stale failure counters.
func (a *Auth) Sweep() {
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, s := range a.sessions {
		if now.After(s.Expires) {
			delete(a.sessions, k)
		}
	}
	for k, f := range a.failures {
		if now.Sub(f.first) > lockoutWindow {
			delete(a.failures, k)
		}
	}
}

func (a *Auth) locked(key string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	f := a.failures[key]
	if f == nil {
		return false
	}
	if time.Since(f.first) > lockoutWindow {
		delete(a.failures, key)
		return false
	}
	return f.count >= maxFailures
}

func (a *Auth) recordFailure(key string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f := a.failures[key]
	if f == nil || time.Since(f.first) > lockoutWindow {
		a.failures[key] = &failure{count: 1, first: time.Now()}
		return
	}
	f.count++
}

func (a *Auth) clearFailures(key string) {
	a.mu.Lock()
	delete(a.failures, key)
	a.mu.Unlock()
}
