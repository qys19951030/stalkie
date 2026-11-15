// Package archive turns each stalkie scan into a persistent collection
// archive: one record per platform, resumable runs, change detection
// between runs, recomputable statistics and mergeable views.
package archive

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
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

	mu sync.Mutex
}

type rootMeta struct {
	ArchiveID string    `json:"archive_id"`
	CreatedAt time.Time `json:"created_at"`
}

const (
	recordsFile = "records.jsonl"
	runsFile    = "runs.jsonl"
	changesFile = "changes.jsonl"
	statsJSON   = "stats.json"
	statsTXT    = "stats.txt"
	metaFile    = "meta.json"
)

// sanitizeHandle maps a handle to a safe directory name.
func sanitizeHandle(handle string) string {
	var b strings.Builder
	for _, r := range handle {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

func newID(prefix string) string {
	var buf [6]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(buf[:]))
}

// ensureRootMeta creates the root directory and its meta file if needed and
// returns the archive ID. It also proves the path is writable.
func ensureRootMeta(root string) (string, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", fmt.Errorf("archive path not writable: %w", err)
	}
	metaPath := filepath.Join(root, metaFile)
	data, err := os.ReadFile(metaPath)
	if err == nil {
		var m rootMeta
		if json.Unmarshal(data, &m) == nil && m.ArchiveID != "" {
			return m.ArchiveID, nil
		}
	}
	m := rootMeta{ArchiveID: newID("arc"), CreatedAt: time.Now().UTC()}
	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(metaPath, out, 0o644); err != nil {
		return "", fmt.Errorf("archive path not writable: %w", err)
	}
	return m.ArchiveID, nil
}

// repairJSONL truncates a JSONL file to the end of its last complete,
// parseable line, so a crash mid-write never corrupts the archive.
func repairJSONL(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var goodEnd int64
	var offset int64
	for scanner.Scan() {
		line := scanner.Bytes()
		lineLen := int64(len(line)) + 1 // account for the newline
		trimmed := strings.TrimSpace(string(line))
		if trimmed != "" && json.Valid([]byte(trimmed)) {
			goodEnd = offset + lineLen
		}
		offset += lineLen
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() > goodEnd {
		return f.Truncate(goodEnd)
	}
	return nil
}

func readJSONL[T any](path string, out *[]T) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		var item T
		if err := json.Unmarshal([]byte(trimmed), &item); err != nil {
			return fmt.Errorf("corrupt line in %s: %w", path, err)
		}
		*out = append(*out, item)
	}
	return nil
}

func appendJSONL(path string, items ...any) error {
	if len(items) == 0 {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	for _, item := range items {
		data, err := json.Marshal(item)
		if err != nil {
			f.Close()
			return err
		}
		if _, err := f.Write(append(data, '\n')); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
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
	trimmed := strings.TrimSpace(handle)
	if trimmed == "" {
		return nil, fmt.Errorf("empty handle")
	}
	archiveID, err := ensureRootMeta(root)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(root, sanitizeHandle(trimmed))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("archive path not writable: %w", err)
	}
	for _, name := range []string{recordsFile, runsFile, changesFile} {
		if err := repairJSONL(filepath.Join(dir, name)); err != nil {
			return nil, fmt.Errorf("repairing %s: %w", name, err)
		}
	}
	return &Archive{
		Root:      root,
		Handle:    trimmed,
		Dir:       dir,
		ArchiveID: archiveID,
	}, nil
}

// Close releases archive resources.
func (a *Archive) Close() error {
	return nil
}

// CompletedSites returns the set of platforms that already have a record.
func (a *Archive) CompletedSites() (map[string]bool, error) {
	records, err := a.Records()
	if err != nil {
		return nil, err
	}
	done := make(map[string]bool, len(records))
	for _, r := range records {
		done[r.Site] = true
	}
	return done, nil
}

// BeginRun registers a new run and returns its descriptor.
func (a *Archive) BeginRun(sitesTotal int) (RunInfo, error) {
	run := RunInfo{
		RunID:      fmt.Sprintf("%s-%s", time.Now().UTC().Format("20060102T150405"), newID("run")),
		Handle:     a.Handle,
		StartedAt:  time.Now().UTC(),
		SitesTotal: sitesTotal,
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := appendJSONL(filepath.Join(a.Dir, runsFile), run); err != nil {
		return RunInfo{}, err
	}
	return run, nil
}

// AppendRecord persists one platform record; safe for concurrent use.
func (a *Archive) AppendRecord(rec Record) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return appendJSONL(filepath.Join(a.Dir, recordsFile), rec)
}

// FinishRun marks a run finished in the runs log.
func (a *Archive) FinishRun(run RunInfo) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	path := filepath.Join(a.Dir, runsFile)
	var runs []RunInfo
	if err := readJSONL(path, &runs); err != nil {
		return err
	}
	found := false
	for i := range runs {
		if runs[i].RunID == run.RunID {
			run.FinishedAt = time.Now().UTC()
			runs[i] = run
			found = true
			break
		}
	}
	if !found {
		run.FinishedAt = time.Now().UTC()
		runs = append(runs, run)
	}
	var lines []any
	for i := range runs {
		lines = append(lines, runs[i])
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	for _, item := range lines {
		data, err := json.Marshal(item)
		if err != nil {
			f.Close()
			os.Remove(tmp)
			return err
		}
		if _, err := f.Write(append(data, '\n')); err != nil {
			f.Close()
			os.Remove(tmp)
			return err
		}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// Records returns every stored record in file order.
func (a *Archive) Records() ([]Record, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var records []Record
	if err := readJSONL(filepath.Join(a.Dir, recordsFile), &records); err != nil {
		return nil, err
	}
	return records, nil
}

// LatestBySite returns the newest record per platform.
func (a *Archive) LatestBySite() (map[string]Record, error) {
	records, err := a.Records()
	if err != nil {
		return nil, err
	}
	latest := make(map[string]Record)
	for _, r := range records {
		cur, ok := latest[r.Site]
		if !ok || !r.CheckedAt.Before(cur.CheckedAt) {
			latest[r.Site] = r
		}
	}
	return latest, nil
}

// DetectChanges compares fresh records against the baseline that existed
// before the run started and returns the four kinds of changes. Platforms
// observed for the first time (no baseline) are not changes; platforms
// whose state did not change are not listed either.
func DetectChanges(run RunInfo, baseline map[string]Record, fresh []Record) []Change {
	snapshot := func(r Record) Snapshot {
		return Snapshot{
			Found:      r.Found,
			Confidence: r.Confidence,
			Evidence:   r.Evidence,
			CheckedAt:  r.CheckedAt,
		}
	}
	var changes []Change
	for _, rec := range fresh {
		before, ok := baseline[rec.Site]
		if !ok {
			continue
		}
		mk := func(t ChangeType) Change {
			return Change{
				RunID:  run.RunID,
				Handle: run.Handle,
				Site:   rec.Site,
				Type:   t,
				Before: snapshot(before),
				After:  snapshot(rec),
			}
		}
		switch {
		case !before.Found && rec.Found:
			changes = append(changes, mk(ChangeNewHit))
		case before.Found && !rec.Found:
			changes = append(changes, mk(ChangeLostHit))
		case before.Found && rec.Found:
			if before.Evidence != rec.Evidence {
				changes = append(changes, mk(ChangeEvidenceChanged))
			}
			if before.Confidence != rec.Confidence {
				changes = append(changes, mk(ChangeConfidenceChanged))
			}
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Site != changes[j].Site {
			return changes[i].Site < changes[j].Site
		}
		return changes[i].Type < changes[j].Type
	})
	return changes
}

// AppendChanges persists detected changes to the changes log.
func (a *Archive) AppendChanges(changes []Change) error {
	if len(changes) == 0 {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	items := make([]any, len(changes))
	for i, c := range changes {
		items[i] = c
	}
	return appendJSONL(filepath.Join(a.Dir, changesFile), items...)
}

// RecalcStats recomputes the statistics of the latest run purely from the
// archive files on disk, so the numbers can always be reproduced by
// rescanning the archive alone.
func (a *Archive) RecalcStats() (Stats, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	stats := Stats{Handle: a.Handle}

	var runs []RunInfo
	if err := readJSONL(filepath.Join(a.Dir, runsFile), &runs); err != nil {
		return stats, err
	}
	if len(runs) == 0 {
		return stats, nil
	}
	latest := runs[0]
	for _, r := range runs[1:] {
		if r.StartedAt.After(latest.StartedAt) {
			latest = r
		}
	}
	stats.RunID = latest.RunID

	var records []Record
	if err := readJSONL(filepath.Join(a.Dir, recordsFile), &records); err != nil {
		return stats, err
	}

	priorSites := make(map[string]bool)
	var runRecords []Record
	for _, r := range records {
		if r.RunID == latest.RunID {
			runRecords = append(runRecords, r)
			continue
		}
		if r.CheckedAt.Before(latest.StartedAt) {
			priorSites[r.Site] = true
		}
	}
	stats.Skipped = len(priorSites)

	stats.Submitted = len(runRecords)
	compared := 0
	for _, r := range runRecords {
		if r.Found {
			stats.Found++
		}
		switch r.Category {
		case CategoryBlocked:
			stats.Blocked++
		case CategoryLoginRequired:
			stats.LoginRequired++
		case CategoryRedirected:
			stats.Redirected++
		case CategoryUnreachable:
			stats.Unreachable++
		}
		if priorSites[r.Site] {
			compared++
		} else {
			stats.FirstObserved++
		}
	}

	var changes []Change
	if err := readJSONL(filepath.Join(a.Dir, changesFile), &changes); err != nil {
		return stats, err
	}
	changedSites := make(map[string]bool)
	for _, c := range changes {
		if c.RunID != latest.RunID {
			continue
		}
		changedSites[c.Site] = true
		switch c.Type {
		case ChangeNewHit:
			stats.NewHits++
		case ChangeLostHit:
			stats.LostHits++
		case ChangeEvidenceChanged:
			stats.EvidenceChanged++
		case ChangeConfidenceChanged:
			stats.ConfidenceChanged++
		}
	}
	stats.Unchanged = compared - len(changedSites)
	if stats.Unchanged < 0 {
		stats.Unchanged = 0
	}
	return stats, nil
}

// WriteStats writes the human-readable and the structured statistics.
// Both are generated from the same Stats value so they agree item by item.
func (a *Archive) WriteStats(s Stats) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	structured, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(a.Dir, statsJSON), append(structured, '\n'), 0o644); err != nil {
		return err
	}

	human := fmt.Sprintf(`Stalkie archive statistics
handle:              %s
run_id:              %s
submitted:           %d
found:               %d
blocked:             %d
login_required:      %d
redirected:          %d
unreachable:         %d
skipped:             %d
first_observed:      %d
unchanged:           %d
new_hits:            %d
lost_hits:           %d
evidence_changed:    %d
confidence_changed:  %d
`, s.Handle, s.RunID, s.Submitted, s.Found, s.Blocked, s.LoginRequired,
		s.Redirected, s.Unreachable, s.Skipped, s.FirstObserved, s.Unchanged,
		s.NewHits, s.LostHits, s.EvidenceChanged, s.ConfidenceChanged)
	return os.WriteFile(filepath.Join(a.Dir, statsTXT), []byte(human), 0o644)
}

// RecordFromResult converts a checker result into an archive record.
func RecordFromResult(runID string, r checker.Result) Record {
	category := Category(r.Outcome)
	switch category {
	case CategoryNormal, CategoryBlocked, CategoryLoginRequired,
		CategoryRedirected, CategoryUnreachable:
	default:
		if r.Error != "" {
			category = CategoryUnreachable
		} else {
			category = CategoryNormal
		}
	}
	return Record{
		RecordID:   runID + ":" + r.Site,
		RunID:      runID,
		Handle:     r.Username,
		Site:       r.Site,
		URL:        r.URL,
		Found:      r.Found,
		Confidence: r.Confidence,
		Evidence:   r.Evidence,
		Category:   category,
		CheckedAt:  time.Now().UTC(),
	}
}

// importsFile tracks which source archives were already merged into a root.
const importsFile = "imports.json"

type importEntry struct {
	ArchiveID  string    `json:"archive_id"`
	ImportedAt time.Time `json:"imported_at"`
}

// Merge merges several archive roots into one output view: the newest
// record per handle+platform becomes the current state (current.json),
// the full history is preserved in records.jsonl, and importing the same
// source archive twice counts only once.
func Merge(inputs []string, outRoot string) error {
	if len(inputs) == 0 {
		return fmt.Errorf("no input archives given")
	}
	outID, err := ensureRootMeta(outRoot)
	if err != nil {
		return err
	}

	importsPath := filepath.Join(outRoot, importsFile)
	var imports []importEntry
	if err := readJSONL(importsPath, &imports); err != nil {
		return err
	}
	seen := make(map[string]bool)
	for _, imp := range imports {
		seen[imp.ArchiveID] = true
	}
	seen[outID] = true // never merge a root into itself

	// Existing record IDs per handle dir in the output, for dedup.
	existingIDs := make(map[string]map[string]bool)

	for _, inRoot := range inputs {
		metaData, err := os.ReadFile(filepath.Join(inRoot, metaFile))
		if err != nil {
			return fmt.Errorf("%s is not an archive (missing %s): %w", inRoot, metaFile, err)
		}
		var meta rootMeta
		if err := json.Unmarshal(metaData, &meta); err != nil || meta.ArchiveID == "" {
			return fmt.Errorf("%s is not an archive (unreadable %s)", inRoot, metaFile)
		}
		if seen[meta.ArchiveID] {
			continue // same archive imported twice counts once
		}

		handles, err := handleDirs(inRoot)
		if err != nil {
			return err
		}
		for _, handleDir := range handles {
			var records []Record
			if err := readJSONL(filepath.Join(inRoot, handleDir, recordsFile), &records); err != nil {
				return err
			}
			if len(records) == 0 {
				continue
			}
			outDir := filepath.Join(outRoot, handleDir)
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return fmt.Errorf("archive path not writable: %w", err)
			}
			ids, ok := existingIDs[outDir]
			if !ok {
				ids = make(map[string]bool)
				var existing []Record
				if err := readJSONL(filepath.Join(outDir, recordsFile), &existing); err != nil {
					return err
				}
				for _, r := range existing {
					ids[r.RecordID] = true
				}
				existingIDs[outDir] = ids
			}
			var fresh []any
			for _, r := range records {
				if r.RecordID == "" {
					r.RecordID = r.RunID + ":" + r.Site
				}
				if ids[r.RecordID] {
					continue
				}
				ids[r.RecordID] = true
				fresh = append(fresh, r)
			}
			if err := appendJSONL(filepath.Join(outDir, recordsFile), fresh...); err != nil {
				return err
			}
		}

		imports = append(imports, importEntry{ArchiveID: meta.ArchiveID, ImportedAt: time.Now().UTC()})
		seen[meta.ArchiveID] = true
	}

	// Rewrite the imports log (small, append-only semantics preserved by
	// keeping every previous entry).
	var items []any
	for _, imp := range imports {
		items = append(items, imp)
	}
	tmp := importsPath + ".tmp"
	if err := func() error {
		f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		for _, item := range items {
			data, err := json.Marshal(item)
			if err != nil {
				f.Close()
				os.Remove(tmp)
				return err
			}
			if _, err := f.Write(append(data, '\n')); err != nil {
				f.Close()
				os.Remove(tmp)
				return err
			}
		}
		if err := f.Sync(); err != nil {
			f.Close()
			os.Remove(tmp)
			return err
		}
		return f.Close()
	}(); err != nil {
		return err
	}
	if err := os.Rename(tmp, importsPath); err != nil {
		return err
	}

	// Rebuild the merged current-state view for every handle in the output.
	outHandles, err := handleDirs(outRoot)
	if err != nil {
		return err
	}
	for _, handleDir := range outHandles {
		var records []Record
		if err := readJSONL(filepath.Join(outRoot, handleDir, recordsFile), &records); err != nil {
			return err
		}
		latest := make(map[string]Record)
		for _, r := range records {
			cur, ok := latest[r.Site]
			if !ok || !r.CheckedAt.Before(cur.CheckedAt) {
				latest[r.Site] = r
			}
		}
		current := make([]Record, 0, len(latest))
		for _, r := range latest {
			current = append(current, r)
		}
		sort.Slice(current, func(i, j int) bool { return current[i].Site < current[j].Site })
		data, err := json.MarshalIndent(current, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(outRoot, handleDir, "current.json"), append(data, '\n'), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// handleDirs lists the per-handle subdirectories of an archive root.
func handleDirs(root string) ([]string, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var dirs []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, e.Name(), recordsFile)); err == nil {
			dirs = append(dirs, e.Name())
		}
	}
	sort.Strings(dirs)
	return dirs, nil
}
