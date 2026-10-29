package web

import (
	"sort"
	"strings"
	"time"
)

// SearchQuery describes a Discover-style log query. All fields are optional;
// an empty query matches every retained event.
type SearchQuery struct {
	Query      string    `json:"query,omitempty"`       // substring, case-insensitive
	Severity   string    `json:"severity,omitempty"`    // "" = all
	Sources    []string  `json:"sources,omitempty"`     // "" = all
	From       time.Time `json:"from,omitempty"`        // zero = unbounded
	To         time.Time `json:"to,omitempty"`          // zero = unbounded
	Limit      int       `json:"limit,omitempty"`       // default 200, max 2000
	SortDesc   bool      `json:"sort_desc,omitempty"`   // newest first
}

const (
	defaultSearchLimit = 200
	maxSearchLimit     = 2000
	histogramBuckets   = 30
)

// Bucket is one column in the Discover histogram.
type Bucket struct {
	Time  time.Time `json:"time"`
	Count int       `json:"count"`
}

// SearchResult is the reply to a discover.search message.
type SearchResult struct {
	Events  []Event   `json:"events"`
	Total   int       `json:"total"`   // matches before Limit
	Buckets []Bucket  `json:"buckets"` // histogram over the matched set
	TookMS  float64   `json:"took_ms"`
}

// match reports whether e satisfies q. Case-insensitive substring match on
// message and source; severity and source are exact (lowercased).
func (q SearchQuery) match(e Event) bool {
	if !q.From.IsZero() && e.Time.Before(q.From) {
		return false
	}
	if !q.To.IsZero() && e.Time.After(q.To) {
		return false
	}
	if q.Severity != "" && !strings.EqualFold(e.Severity, q.Severity) {
		return false
	}
	if len(q.Sources) > 0 {
		found := false
		for _, s := range q.Sources {
			if strings.EqualFold(e.Source, s) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if q.Query != "" {
		needle := strings.ToLower(q.Query)
		if !strings.Contains(strings.ToLower(e.Message), needle) &&
			!strings.Contains(strings.ToLower(e.Source), needle) {
			return false
		}
	}
	return true
}

// Search filters the retained event ring. It runs against Recent() so the
// caller does not hold the hub lock while sorting.
func (h *Hub) Search(q SearchQuery) SearchResult {
	start := time.Now()

	all := h.Recent()
	matched := make([]Event, 0, len(all))
	for _, e := range all {
		if q.match(e) {
			matched = append(matched, e)
		}
	}

	// Histogram over the matched set, before limiting, so the shape reflects
	// the full result rather than the visible page.
	buckets := buildHistogram(matched, q.From, q.To, histogramBuckets)

	sort.SliceStable(matched, func(i, j int) bool {
		if q.SortDesc {
			return matched[i].Time.After(matched[j].Time)
		}
		return matched[i].Time.Before(matched[j].Time)
	})

	limit := q.Limit
	if limit <= 0 {
		limit = defaultSearchLimit
	}
	if limit > maxSearchLimit {
		limit = maxSearchLimit
	}
	total := len(matched)
	if len(matched) > limit {
		matched = matched[:limit]
	}

	return SearchResult{
		Events:  matched,
		Total:   total,
		Buckets: buckets,
		TookMS:  float64(time.Since(start).Microseconds()) / 1000.0,
	}
}

func buildHistogram(events []Event, from, to time.Time, n int) []Bucket {
	if len(events) == 0 {
		return nil
	}
	// Infer the time window from the data when the caller did not supply one.
	lo, hi := from, to
	if lo.IsZero() {
		lo = events[0].Time
		for _, e := range events[1:] {
			if e.Time.Before(lo) {
				lo = e.Time
			}
		}
	}
	if hi.IsZero() {
		hi = events[0].Time
		for _, e := range events[1:] {
			if e.Time.After(hi) {
				hi = e.Time
			}
		}
	}
	if !hi.After(lo) {
		return []Bucket{{Time: lo, Count: len(events)}}
	}
	width := hi.Sub(lo) / time.Duration(n)
	if width <= 0 {
		width = time.Second
	}
	out := make([]Bucket, n)
	for i := range out {
		out[i].Time = lo.Add(time.Duration(i) * width)
	}
	for _, e := range events {
		idx := int(e.Time.Sub(lo) / width)
		if idx < 0 {
			idx = 0
		}
		if idx >= n {
			idx = n - 1
		}
		out[idx].Count++
	}
	return out
}