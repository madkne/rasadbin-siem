package storage

import "time"

// AuthUser stores password verifiers, never plaintext passwords.
type AuthUser struct {
	Username  string `gorm:"primaryKey;size:128"`
	Role      string `gorm:"not null;size:32"`
	Salt      []byte `gorm:"not null"`
	Hash      []byte `gorm:"not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (AuthUser) TableName() string { return "users" }
