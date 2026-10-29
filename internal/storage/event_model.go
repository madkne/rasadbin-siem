package storage

import "time"

// Event mirrors the events table.
type Event struct {
	ID       uint      `gorm:"primaryKey"`
	Time     time.Time `gorm:"index:idx_events_time,sort:desc;not null"`
	Source   string    `gorm:"index:idx_events_source,sort:desc;not null"`
	Severity string    `gorm:"index:idx_events_severity,sort:desc;not null"`
	Message  string    `gorm:"not null"`
}

func (Event) TableName() string { return "events" }
