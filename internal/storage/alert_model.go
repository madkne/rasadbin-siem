package storage

import "time"

// AlertRecord is the durable representation of a detection alert.
type AlertRecord struct {
	ID          string    `gorm:"primaryKey;size:64"`
	RuleID      string    `gorm:"index;not null;size:128"`
	Title       string    `gorm:"not null;size:512"`
	Description string    `gorm:"type:text"`
	Severity    string    `gorm:"index;not null;size:16"`
	FirstSeen   time.Time `gorm:"index;not null"`
	LastSeen    time.Time `gorm:"index;not null"`
	Count       int       `gorm:"not null;default:1"`
	Source      string    `gorm:"index;not null;size:128"`
	SourceIP    string    `gorm:"index;size:64"`
	Evidence    string    `gorm:"type:text"`
	Status      string    `gorm:"index;not null;size:32"`
	Assignee    string    `gorm:"index;size:128"`
	ResolvedAt  *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time `gorm:"index"`
}

func (AlertRecord) TableName() string { return "alerts" }

// AlertNote stores analyst comments separately so alert updates remain small.
type AlertNote struct {
	ID        uint      `gorm:"primaryKey"`
	AlertID   string    `gorm:"index;not null;size:64"`
	Author    string    `gorm:"not null;size:128"`
	Body      string    `gorm:"type:text;not null"`
	CreatedAt time.Time `gorm:"index;not null"`
}

func (AlertNote) TableName() string { return "alert_notes" }

// AlertHistory is an append-only audit trail for workflow changes.
type AlertHistory struct {
	ID         uint      `gorm:"primaryKey"`
	AlertID    string    `gorm:"index;not null;size:64"`
	Action     string    `gorm:"not null;size:32"`
	FromStatus string    `gorm:"size:32"`
	ToStatus   string    `gorm:"size:32"`
	Actor      string    `gorm:"size:128"`
	Details    string    `gorm:"type:text"`
	CreatedAt  time.Time `gorm:"index;not null"`
}

func (AlertHistory) TableName() string { return "alert_history" }
