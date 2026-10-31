package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"rasadbin/internal/detection"
	"rasadbin/internal/web"

	"gorm.io/gorm"
)

// UpsertAlert persists a detection result. Repeated detections update the same
// record while preserving analyst-owned workflow fields (status and assignee).
func (s *Store) UpsertAlert(ctx context.Context, a detection.Alert) (detection.Alert, error) {
	if strings.TrimSpace(a.ID) == "" {
		return detection.Alert{}, errors.New("alert id is required")
	}
	if a.FirstSeen.IsZero() {
		a.FirstSeen = time.Now().UTC()
	}
	if a.LastSeen.IsZero() {
		a.LastSeen = a.FirstSeen
	}
	if a.Count < 1 {
		a.Count = 1
	}
	evidence, err := json.Marshal(a.Evidence)
	if err != nil {
		return detection.Alert{}, fmt.Errorf("encode alert evidence: %w", err)
	}
	var result AlertRecord
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var row AlertRecord
		err := tx.Where("id = ?", a.ID).First(&row).Error
		switch {
		case errors.Is(err, gorm.ErrRecordNotFound):
			status := strings.TrimSpace(a.Status)
			if status == "" || status == "open" {
				status = "new"
			}
			row = AlertRecord{
				ID: a.ID, RuleID: a.RuleID, Title: a.Title, Description: a.Description,
				Severity: a.Severity, FirstSeen: a.FirstSeen.UTC(), LastSeen: a.LastSeen.UTC(),
				Count: a.Count, Source: a.Source, SourceIP: a.SourceIP,
				Evidence: string(evidence), Status: status,
			}
			if err := tx.Create(&row).Error; err != nil {
				return err
			}
			h := AlertHistory{AlertID: a.ID, Action: "created", Actor: "detection-engine", Details: "Detection rule generated an alert", CreatedAt: time.Now().UTC()}
			if err := tx.Create(&h).Error; err != nil {
				return err
			}
		case err != nil:
			return err
		default:
			// Detection owns these fields. Analysts own status and assignee.
			row.RuleID, row.Title, row.Description = a.RuleID, a.Title, a.Description
			row.Severity, row.Source, row.SourceIP = a.Severity, a.Source, a.SourceIP
			if a.LastSeen.After(row.LastSeen) {
				row.LastSeen = a.LastSeen.UTC()
			}
			if a.Count > row.Count {
				row.Count = a.Count
			}
			var mergedEvidence []string
			_ = json.Unmarshal([]byte(row.Evidence), &mergedEvidence)
			seenEvidence := make(map[string]struct{}, len(mergedEvidence))
			for _, item := range mergedEvidence {
				seenEvidence[item] = struct{}{}
			}
			for _, item := range a.Evidence {
				if len(mergedEvidence) >= 5 {
					break
				}
				if _, exists := seenEvidence[item]; !exists {
					mergedEvidence = append(mergedEvidence, item)
					seenEvidence[item] = struct{}{}
				}
			}
			merged, _ := json.Marshal(mergedEvidence)
			row.Evidence = string(merged)
			if row.FirstSeen.IsZero() || a.FirstSeen.Before(row.FirstSeen) {
				row.FirstSeen = a.FirstSeen.UTC()
			}
			if err := tx.Save(&row).Error; err != nil {
				return err
			}
		}
		result = row
		return nil
	})
	if err != nil {
		return detection.Alert{}, fmt.Errorf("persist alert: %w", err)
	}
	return alertFromRecord(result), nil
}

// ListAlerts returns newest alerts first with optional filters.
func (s *Store) ListAlerts(ctx context.Context, q web.AlertQuery) ([]detection.Alert, int, error) {
	db := s.db.WithContext(ctx).Model(&AlertRecord{})
	if q.Severity != "" {
		db = db.Where("LOWER(severity) = LOWER(?)", q.Severity)
	}
	if q.Status != "" {
		db = db.Where("LOWER(status) = LOWER(?)", q.Status)
	}
	if q.Search != "" {
		like := "%" + strings.ToLower(strings.TrimSpace(q.Search)) + "%"
		db = db.Where("LOWER(title) LIKE ? OR LOWER(description) LIKE ? OR LOWER(source) LIKE ? OR LOWER(rule_id) LIKE ? OR LOWER(source_ip) LIKE ?", like, like, like, like, like)
	}
	var total int64
	if err := db.Count(&total).Error; err != nil {
		return nil, 0, fmt.Errorf("count alerts: %w", err)
	}
	limit := q.Limit
	if limit <= 0 {
		limit = 200
	}
	if limit > 500 {
		limit = 500
	}
	offset := q.Offset
	if offset < 0 {
		offset = 0
	}
	var rows []AlertRecord
	if err := db.Order("last_seen DESC").Limit(limit).Offset(offset).Find(&rows).Error; err != nil {
		return nil, 0, fmt.Errorf("list alerts: %w", err)
	}
	out := make([]detection.Alert, 0, len(rows))
	for _, row := range rows {
		out = append(out, alertFromRecord(row))
	}
	return out, int(total), nil
}

// UpdateAlert changes analyst workflow fields and appends an audit record.
func (s *Store) UpdateAlert(ctx context.Context, id, status, assignee, actor string) (detection.Alert, error) {
	status = strings.ToLower(strings.TrimSpace(status))
	assignee = strings.TrimSpace(assignee)
	if len(assignee) > 128 {
		return detection.Alert{}, errors.New("assignee is too long (maximum 128 characters)")
	}
	switch status {
	case "new", "acknowledged", "investigating", "resolved", "false_positive":
	default:
		return detection.Alert{}, fmt.Errorf("invalid alert status %q", status)
	}
	var result AlertRecord
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var row AlertRecord
		if err := tx.Where("id = ?", id).First(&row).Error; err != nil {
			return err
		}
		oldStatus, oldAssignee := row.Status, row.Assignee
		row.Status, row.UpdatedAt = status, time.Now().UTC()
		row.Assignee = assignee
		if status == "resolved" || status == "false_positive" {
			now := time.Now().UTC()
			row.ResolvedAt = &now
		} else {
			row.ResolvedAt = nil
		}
		if err := tx.Save(&row).Error; err != nil {
			return err
		}
		if oldStatus != status {
			h := AlertHistory{AlertID: id, Action: "status_changed", FromStatus: oldStatus, ToStatus: status, Actor: actor, CreatedAt: time.Now().UTC()}
			if err := tx.Create(&h).Error; err != nil {
				return err
			}
		}
		if oldAssignee != row.Assignee {
			h := AlertHistory{AlertID: id, Action: "assignment_changed", Actor: actor, Details: fmt.Sprintf("Assignee: %s → %s", oldAssignee, row.Assignee), CreatedAt: time.Now().UTC()}
			if err := tx.Create(&h).Error; err != nil {
				return err
			}
		}
		result = row
		return nil
	})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return detection.Alert{}, errors.New("alert not found")
	}
	if err != nil {
		return detection.Alert{}, fmt.Errorf("update alert: %w", err)
	}
	return alertFromRecord(result), nil
}

func (s *Store) AddAlertNote(ctx context.Context, id, author, body string) (web.AlertNote, error) {
	body = strings.TrimSpace(body)
	if body == "" {
		return web.AlertNote{}, errors.New("note cannot be empty")
	}
	if len(body) > 10000 {
		return web.AlertNote{}, errors.New("note is too long (maximum 10000 characters)")
	}
	var note AlertNote
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var count int64
		if err := tx.Model(&AlertRecord{}).Where("id = ?", id).Count(&count).Error; err != nil {
			return err
		}
		if count == 0 {
			return gorm.ErrRecordNotFound
		}
		note = AlertNote{AlertID: id, Author: author, Body: body, CreatedAt: time.Now().UTC()}
		if err := tx.Create(&note).Error; err != nil {
			return err
		}
		h := AlertHistory{AlertID: id, Action: "note_added", Actor: author, Details: "Analyst note added", CreatedAt: note.CreatedAt}
		return tx.Create(&h).Error
	})
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return web.AlertNote{}, errors.New("alert not found")
	}
	if err != nil {
		return web.AlertNote{}, fmt.Errorf("add alert note: %w", err)
	}
	return web.AlertNote{ID: note.ID, AlertID: note.AlertID, Author: note.Author, Body: note.Body, CreatedAt: note.CreatedAt}, nil
}

func (s *Store) ListAlertNotes(ctx context.Context, id string) ([]web.AlertNote, error) {
	var rows []AlertNote
	if err := s.db.WithContext(ctx).Where("alert_id = ?", id).Order("created_at ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list alert notes: %w", err)
	}
	out := make([]web.AlertNote, 0, len(rows))
	for _, n := range rows {
		out = append(out, web.AlertNote{ID: n.ID, AlertID: n.AlertID, Author: n.Author, Body: n.Body, CreatedAt: n.CreatedAt})
	}
	return out, nil
}

func alertFromRecord(row AlertRecord) detection.Alert {
	var evidence []string
	_ = json.Unmarshal([]byte(row.Evidence), &evidence)
	return detection.Alert{ID: row.ID, RuleID: row.RuleID, Title: row.Title, Description: row.Description,
		Severity: row.Severity, FirstSeen: row.FirstSeen, LastSeen: row.LastSeen, Count: row.Count,
		Source: row.Source, SourceIP: row.SourceIP, Evidence: evidence, Status: row.Status,
		Assignee: row.Assignee, UpdatedAt: row.UpdatedAt, ResolvedAt: row.ResolvedAt}
}

// ListAlertHistory returns the append-only audit trail for an alert.
func (s *Store) ListAlertHistory(ctx context.Context, id string) ([]web.AlertHistoryEntry, error) {
	var rows []AlertHistory
	if err := s.db.WithContext(ctx).Where("alert_id = ?", id).Order("created_at ASC").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("list alert history: %w", err)
	}
	out := make([]web.AlertHistoryEntry, 0, len(rows))
	for _, h := range rows {
		out = append(out, web.AlertHistoryEntry{ID: h.ID, AlertID: h.AlertID, Action: h.Action, FromStatus: h.FromStatus, ToStatus: h.ToStatus, Actor: h.Actor, Details: h.Details, CreatedAt: h.CreatedAt})
	}
	return out, nil
}

var _ web.AlertStore = (*Store)(nil)
