package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"rasadbin/internal/asset"

	"gorm.io/gorm/clause"
)

// AssetRecord is the durable form of an asset. List-valued fields are stored
// as JSON text so the schema works unchanged on SQLite, PostgreSQL and MySQL.
type AssetRecord struct {
	ID          string    `gorm:"primaryKey;size:300"`
	Origin      string    `gorm:"index;not null;size:16"`
	Name        string    `gorm:"not null;size:300"`
	Hostname    string    `gorm:"index;size:253"`
	IPs         string    `gorm:"column:ips;type:text"`
	Ports       string    `gorm:"column:ports;type:text"`
	Sources     string    `gorm:"column:sources;type:text"`
	Tags        string    `gorm:"column:tags;type:text"`
	Criticality string    `gorm:"size:16"`
	FirstSeen   time.Time `gorm:"not null"`
	LastSeen    time.Time `gorm:"index;not null"`
	EventCount  int64     `gorm:"not null;default:0"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

func (AssetRecord) TableName() string { return "assets" }

// SaveAssets upserts a batch. created_at is deliberately not in the update set.
func (s *Store) SaveAssets(ctx context.Context, items []asset.Asset) error {
	if len(items) == 0 {
		return nil
	}
	rows := make([]AssetRecord, 0, len(items))
	for _, a := range items {
		rows = append(rows, assetToRecord(a))
	}
	err := s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "id"}},
		DoUpdates: clause.AssignmentColumns([]string{
			"origin", "name", "hostname", "ips", "ports", "sources", "tags",
			"criticality", "first_seen", "last_seen", "event_count", "updated_at",
		}),
	}).CreateInBatches(rows, 100).Error
	if err != nil {
		return fmt.Errorf("save assets: %w", err)
	}
	return nil
}

// LoadAssets returns every stored asset (the service caps the inventory size).
func (s *Store) LoadAssets(ctx context.Context) ([]asset.Asset, error) {
	var rows []AssetRecord
	if err := s.db.WithContext(ctx).Order("last_seen DESC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("load assets: %w", err)
	}
	out := make([]asset.Asset, 0, len(rows))
	for _, r := range rows {
		out = append(out, recordToAsset(r))
	}
	return out, nil
}

func assetToRecord(a asset.Asset) AssetRecord {
	enc := func(v any) string { b, _ := json.Marshal(v); return string(b) }
	return AssetRecord{
		ID: a.ID, Origin: a.Origin, Name: a.Name, Hostname: a.Hostname,
		IPs: enc(nz(a.IPs)), Ports: enc(nzInt(a.Ports)), Sources: enc(nz(a.Sources)), Tags: enc(nz(a.Tags)),
		Criticality: a.Criticality, FirstSeen: a.FirstSeen.UTC(), LastSeen: a.LastSeen.UTC(),
		EventCount: a.EventCount,
	}
}

func recordToAsset(r AssetRecord) asset.Asset {
	a := asset.Asset{
		ID: r.ID, Origin: r.Origin, Name: r.Name, Hostname: r.Hostname,
		Criticality: r.Criticality, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen,
		EventCount: r.EventCount,
	}
	_ = json.Unmarshal([]byte(r.IPs), &a.IPs)
	_ = json.Unmarshal([]byte(r.Ports), &a.Ports)
	_ = json.Unmarshal([]byte(r.Sources), &a.Sources)
	_ = json.Unmarshal([]byte(r.Tags), &a.Tags)
	return a
}

func nz(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func nzInt(v []int) []int {
	if v == nil {
		return []int{}
	}
	return v
}

var _ asset.Store = (*Store)(nil)
