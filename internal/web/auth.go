package web

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

const (
	pbkdf2Iterations = 600_000
	maxFailures      = 5
	lockoutWindow    = 5 * time.Minute
	minPasswordLen   = 8
	maxPasswordLen   = 128
)

var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrTooManyAttempts    = errors.New("too many failed attempts")
	ErrWeakPassword       = errors.New("new password must be 8-128 characters")
)

type AuthUserRecord struct {
	Username string
	Role     string
	Salt     []byte
	Hash     []byte
}

type AuthSessionRecord struct {
	TokenHash string
	Username  string
	Role      string
	Expires   time.Time
}

// AuthRepository is implemented by the persistent storage package.
type AuthRepository interface {
	LoadAuthState() ([]AuthUserRecord, []AuthSessionRecord, error)
	HasAuthUsers() (bool, error)
	SaveAuthUser(AuthUserRecord) error
	SaveAuthSession(AuthSessionRecord) error
	DeleteAuthSession(tokenHash string) error
	DeleteAuthSessions(username string) error
}

type user struct {
	name string
	role string
	salt []byte
	hash []byte
}

type Session struct {
	Username string
	Role     string
	Expires  time.Time
}

type failure struct {
	count int
	first time.Time
}

type Auth struct {
	mu       sync.Mutex
	users    map[string]*user
	sessions map[[32]byte]*Session
	failures map[string]*failure
	ttl      func() time.Duration
	dummy    *user
	repo     AuthRepository
}

// NewAuth preserves the in-memory constructor for isolated tests.
func NewAuth(adminPassword string, ttl func() time.Duration) (*Auth, error) {
	return newAuth(adminPassword, ttl, nil)
}

// NewAuthWithRepository restores users and non-expired sessions from the DB.
// The initial admin is created only when the users table is empty.
func NewAuthWithRepository(adminPassword string, ttl func() time.Duration, repo AuthRepository) (*Auth, error) {
	if repo == nil {
		return nil, errors.New("auth repository is required")
	}
	return newAuth(adminPassword, ttl, repo)
}

func newAuth(adminPassword string, ttl func() time.Duration, repo AuthRepository) (*Auth, error) {
	if ttl == nil {
		ttl = func() time.Duration { return 30 * time.Minute }
	}
	a := &Auth{
		users: make(map[string]*user), sessions: make(map[[32]byte]*Session),
		failures: make(map[string]*failure), ttl: ttl, repo: repo,
	}
	dummy, err := newUser("", "", randomToken())
	if err != nil {
		return nil, err
	}
	a.dummy = dummy

	if repo != nil {
		users, sessions, err := repo.LoadAuthState()
		if err != nil {
			return nil, err
		}
		for _, row := range users {
			if row.Username == "" || len(row.Salt) == 0 || len(row.Hash) == 0 {
				continue
			}
			a.users[row.Username] = &user{name: row.Username, role: row.Role, salt: append([]byte(nil), row.Salt...), hash: append([]byte(nil), row.Hash...)}
		}
		for _, row := range sessions {
			keyBytes, err := hex.DecodeString(row.TokenHash)
			if err != nil || len(keyBytes) != 32 || time.Now().After(row.Expires) {
				continue
			}
			var key [32]byte
			copy(key[:], keyBytes)
			a.sessions[key] = &Session{Username: row.Username, Role: row.Role, Expires: row.Expires}
		}
	}
	if len(a.users) == 0 {
		if len(adminPassword) < minPasswordLen || len(adminPassword) > maxPasswordLen {
			return nil, ErrWeakPassword
		}
		admin, err := newUser("admin", "admin", adminPassword)
		if err != nil {
			return nil, err
		}
		if repo != nil {
			if err := repo.SaveAuthUser(AuthUserRecord{Username: admin.name, Role: admin.role, Salt: admin.salt, Hash: admin.hash}); err != nil {
				return nil, err
			}
		}
		a.users["admin"] = admin
	}
	return a, nil
}

func newUser(name, role, password string) (*user, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
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
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func hashToken(t string) [32]byte { return sha256.Sum256([]byte(t)) }
func tokenHashString(t string) string {
	h := hashToken(t)
	return hex.EncodeToString(h[:])
}

func (a *Auth) Login(username, password, ip string) (string, Session, error) {
	if len(username) > 128 || len(password) > maxPasswordLen || len(password) < 1 {
		a.recordFailure(ip)
		return "", Session{}, ErrInvalidCredentials
	}
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
	if token == "" {
		return "", Session{}, errors.New("could not generate session token")
	}
	s := Session{Username: u.name, Role: u.role, Expires: time.Now().Add(a.ttl()).UTC()}
	if a.repo != nil {
		if err := a.repo.SaveAuthSession(AuthSessionRecord{TokenHash: tokenHashString(token), Username: s.Username, Role: s.Role, Expires: s.Expires}); err != nil {
			return "", Session{}, err
		}
	}
	a.mu.Lock()
	a.sessions[hashToken(token)] = &s
	a.mu.Unlock()
	return token, s, nil
}

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
		if a.repo != nil {
			_ = a.repo.DeleteAuthSession(hex.EncodeToString(key[:]))
		}
		return nil, false
	}
	cp := *s
	return &cp, true
}

func (a *Auth) Logout(token string) {
	if token == "" {
		return
	}
	key := hashToken(token)
	a.mu.Lock()
	delete(a.sessions, key)
	a.mu.Unlock()
	if a.repo != nil {
		_ = a.repo.DeleteAuthSession(hex.EncodeToString(key[:]))
	}
}

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
	if a.repo != nil {
		if err := a.repo.SaveAuthUser(AuthUserRecord{Username: nu.name, Role: nu.role, Salt: nu.salt, Hash: nu.hash}); err != nil {
			return err
		}
		if err := a.repo.DeleteAuthSessions(username); err != nil {
			return err
		}
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

func (a *Auth) Sweep() {
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, s := range a.sessions {
		if now.After(s.Expires) {
			delete(a.sessions, k)
			if a.repo != nil {
				_ = a.repo.DeleteAuthSession(hex.EncodeToString(k[:]))
			}
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
func (a *Auth) clearFailures(key string) { a.mu.Lock(); delete(a.failures, key); a.mu.Unlock() }
