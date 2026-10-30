package storage

import "time"

// AuthSession stores only a SHA-256 token digest, not the bearer token.
type AuthSession struct {
	TokenHash string    `gorm:"primaryKey;size:64"`
	Username  string    `gorm:"index;not null;size:128"`
	Role      string    `gorm:"not null;size:32"`
	Expires   time.Time `gorm:"index;not null"`
	CreatedAt time.Time
}

func (AuthSession) TableName() string { return "auth_sessions" }
