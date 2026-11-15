// Package archive turns each stalkie scan into a persistent collection
// archive: one record per platform, resumable runs, change detection
// between runs, recomputable statistics and mergeable views.
package archive

import (
	"time"

	"github.com/ashendilantha/stalkie/checker"
	"github.com/ashendilantha/stalkie/loader"
)

// Category classifies how the request for a single platform ended up.
type Category string

const (
	CategoryNormal        Category = "normal"
	CategoryBlocked       Category = "blocked"
	CategoryLoginRequired Category = "login_required"
	CategoryRedirected    Category = "redirected"
	CategoryUnreachable   Category = "unreachable"
)

// ChangeType enumerates the four diff kinds between two runs.
type ChangeType string

const (
	ChangeNewHit            ChangeType = "new_hit"
	ChangeLostHit           ChangeType = "lost_hit"
	ChangeEvidenceChanged   ChangeType = "evidence_changed"
	ChangeConfidenceChanged ChangeType = "confidence_changed"
)

// Record is one platform observation inside an archive.
type Record struct {
	RecordID   string    `json:"record_id"`
	RunID      string    `json:"run_id"`
	Handle     string    `json:"handle"`
	Site       string    `json:"site"`
	URL        string    `json:"url"`
	Found      bool      `json:"found"`
	Confidence int       `json:"confidence"`
	Evidence   string    `json:"evidence"`
	Category   Category  `json:"category"`
	CheckedAt  time.Time `json:"checked_at"`
}

// RunInfo describes one scan run against an archive.
type RunInfo struct {
	RunID      string    `json:"run_id"`
	Handle     string    `json:"handle"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	SitesTotal int       `json:"sites_total"`
}

// Snapshot is the before/after state carried by a Change.
type Snapshot struct {
	Found      bool      `json:"found"`
	Confidence int       `json:"confidence"`
	Evidence   string    `json:"evidence"`
	CheckedAt  time.Time `json:"checked_at"`
}

// Change is one detected difference for one platform.
type Change struct {
	RunID  string     `json:"run_id"`
	Handle string     `json:"handle"`
	Site   string     `json:"site"`
	Type   ChangeType `json:"type"`
	Before Snapshot   `json:"before"`
	After  Snapshot   `json:"after"`
}

// Stats is the recomputable summary of the latest run of one handle.
type Stats struct {
	Handle             string `json:"handle"`
	RunID              string `json:"run_id"`
	Submitted          int    `json:"submitted"`
	Found              int    `json:"found"`
	Blocked            int    `json:"blocked"`
	LoginRequired      int    `json:"login_required"`
	Redirected         int    `json:"redirected"`
	Unreachable        int    `json:"unreachable"`
	Skipped            int    `json:"skipped"`
	FirstObserved      int    `json:"first_observed"`
	Unchanged          int    `json:"unchanged"`
	NewHits            int    `json:"new_hits"`
	LostHits           int    `json:"lost_hits"`
	EvidenceChanged    int    `json:"evidence_changed"`
	ConfidenceChanged  int    `json:"confidence_changed"`
}

// Archive is an opened per-handle collection directory.
type Archive struct {
	Root      string
	Handle    string
	Dir       string
	ArchiveID string
}

// Validate checks all preconditions before any request is made:
// archive path writable, handles non-empty, site database non-empty and
// every platform already recorded in the archive present in the site DB.
func Validate(root string, handles []string, sites []loader.Site) error {
	return nil
}

// Open opens (or creates) the archive directory for one handle, repairing
// a partially written records file by truncating to the last full record.
func Open(root, handle string) (*Archive, error) {
	return nil, nil
}

// Close releases archive resources.
func (a *Archive) Close() error {
	return nil
}

// CompletedSites returns the set of platforms that already have a record.
func (a *Archive) CompletedSites() (map[string]bool, error) {
	return nil, nil
}

// BeginRun registers a new run and returns its descriptor.
func (a *Archive) BeginRun(sitesTotal int) (RunInfo, error) {
	return RunInfo{}, nil
}

// AppendRecord persists one platform record; safe for concurrent use.
func (a *Archive) AppendRecord(rec Record) error {
	return nil
}

// FinishRun marks a run finished in the runs log.
func (a *Archive) FinishRun(run RunInfo) error {
	return nil
}

// Records returns every stored record in file order.
func (a *Archive) Records() ([]Record, error) {
	return nil, nil
}

// LatestBySite returns the newest record per platform.
func (a *Archive) LatestBySite() (map[string]Record, error) {
	return nil, nil
}

// DetectChanges compares fresh records against the baseline that existed
// before the run started and returns the four kinds of changes.
func DetectChanges(run RunInfo, baseline map[string]Record, fresh []Record) []Change {
	return nil
}

// AppendChanges persists detected changes to the changes log.
func (a *Archive) AppendChanges(changes []Change) error {
	return nil
}

// RecalcStats recomputes the statistics of the latest run purely from the
// archive files on disk.
func (a *Archive) RecalcStats() (Stats, error) {
	return Stats{}, nil
}

// WriteStats writes the human-readable and the structured statistics.
func (a *Archive) WriteStats(s Stats) error {
	return nil
}

// RecordFromResult converts a checker result into an archive record.
func RecordFromResult(runID string, r checker.Result) Record {
	return Record{}
}

// Merge merges several archive roots into one output view: newest record
// per handle+platform is the current state, history is preserved, and the
// same source archive imported twice counts only once.
func Merge(inputs []string, outRoot string) error {
	return nil
}
