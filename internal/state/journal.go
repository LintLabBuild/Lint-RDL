// Package state persists jobs (the journal), the audit log and the
// single-instance lock.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// JobState is the life-cycle state of a job.
type JobState string

// Job states.
const (
	StateQueued      JobState = "queued"
	StateRunning     JobState = "running"
	StateRetrying    JobState = "retrying"     // waiting before the next attempt
	StatePaused      JobState = "paused"       // paused by a user
	StatePausedDisk  JobState = "paused-disk"  // waiting for free space
	StatePausedNoDir JobState = "paused-nodir" // save folder vanished
	StateVerifying   JobState = "verifying"
	StateDone        JobState = "done"
	StateFailed      JobState = "failed"
	StateCancelled   JobState = "cancelled"
)

// Terminal reports whether no more work will happen without user action.
func (s JobState) Terminal() bool {
	return s == StateDone || s == StateFailed || s == StateCancelled
}

// Job is everything rdl must remember to resume a download after a crash.
type Job struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind,omitempty"`      // "" = file over HTTP, "git" = repository clone
	URL       string    `json:"url"`                 // original URL, re-requested on every attempt
	FinalURL  string    `json:"final_url,omitempty"` // last URL after redirects (informational)
	Dir       string    `json:"dir"`                 // real, checked save folder
	Name      string    `json:"name"`                // cleaned file name (may still change if taken)
	NameFixed bool      `json:"name_fixed,omitempty"`
	PartPath  string    `json:"part_path"`
	Owner     string    `json:"owner,omitempty"` // identity that added the job
	Via       string    `json:"via,omitempty"`   // interface (cli, web, telegram, mcp)
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	ExpectedSize   int64  `json:"expected_size"` // -1 unknown
	ExpectedSHA256 string `json:"expected_sha256,omitempty"`
	ETag           string `json:"etag,omitempty"`
	LastModified   string `json:"last_modified,omitempty"`
	Resumable      bool   `json:"resumable"`
	// ResumeMode decides what happens when the server can't resume:
	// "" (manager default), auto, ratchet, missing-only, restart.
	ResumeMode string `json:"resume_mode,omitempty"`
	// RangeBroken: the server answers range requests wrongly, so rdl stops
	// asking for ranges (and relies on the ratchet).
	RangeBroken bool `json:"range_broken,omitempty"`
	// VerifyPrefix: the link was replaced (relink) and the saved part has
	// not yet been checked against the new server.
	VerifyPrefix bool `json:"verify_prefix,omitempty"`

	Written   int64  `json:"written"`              // bytes durably on disk (fsync'd)
	HashState []byte `json:"hash_state,omitempty"` // sha256 state at Written

	State    JobState `json:"state"`
	Error    string   `json:"error,omitempty"`
	Notice   string   `json:"notice,omitempty"` // e.g. "file changed on server, restarted"
	Attempts int      `json:"attempts"`

	GitURL    string `json:"git_url,omitempty"`
	GitRef    string `json:"git_ref,omitempty"`
	GitFull   bool   `json:"git_full,omitempty"`
	Commit    string `json:"commit,omitempty"`
	FileCount int    `json:"file_count,omitempty"`

	FinalPath string    `json:"final_path,omitempty"`
	SHA256    string    `json:"sha256,omitempty"` // computed hash of the finished file
	Verified  bool      `json:"verified,omitempty"`
	DoneAt    time.Time `json:"done_at,omitempty"`
}

var idRe = regexp.MustCompile(`^[a-z0-9]{4,32}$`)

// ValidID reports whether id is a well-formed job id.
func ValidID(id string) bool { return idRe.MatchString(id) }

// Journal stores one JSON file per job, written atomically
// (temp file + fsync + rename), so a crash never leaves a torn entry.
type Journal struct {
	dir string
	mu  sync.Mutex
}

// OpenJournal opens (and creates) a journal folder.
func OpenJournal(dir string) (*Journal, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Journal{dir: dir}, nil
}

// Dir returns the journal folder.
func (j *Journal) Dir() string { return j.dir }

func (j *Journal) path(id string) string { return filepath.Join(j.dir, id+".json") }

// Save writes job atomically.
func (j *Journal) Save(job *Job) error {
	if !ValidID(job.ID) {
		return fmt.Errorf("invalid job id %q", job.ID)
	}
	data, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		return err
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return WriteFileAtomic(j.path(job.ID), data, 0o600)
}

// Load reads one job.
func (j *Journal) Load(id string) (*Job, error) {
	if !ValidID(id) {
		return nil, fmt.Errorf("invalid job id %q", id)
	}
	data, err := os.ReadFile(j.path(id))
	if err != nil {
		return nil, err
	}
	var job Job
	if err := json.Unmarshal(data, &job); err != nil {
		return nil, fmt.Errorf("journal entry %s is corrupt: %w", id, err)
	}
	return &job, nil
}

// Delete removes a job's entry.
func (j *Journal) Delete(id string) error {
	if !ValidID(id) {
		return fmt.Errorf("invalid job id %q", id)
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	err := os.Remove(j.path(id))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// All returns every job, oldest first. Corrupt entries are skipped and
// reported in the second return value.
func (j *Journal) All() ([]*Job, []error) {
	des, err := os.ReadDir(j.dir)
	if err != nil {
		return nil, []error{err}
	}
	var jobs []*Job
	var errs []error
	for _, de := range des {
		name := de.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		job, err := j.Load(strings.TrimSuffix(name, ".json"))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		jobs = append(jobs, job)
	}
	sort.Slice(jobs, func(a, b int) bool {
		if jobs[a].CreatedAt.Equal(jobs[b].CreatedAt) {
			return jobs[a].ID < jobs[b].ID
		}
		return jobs[a].CreatedAt.Before(jobs[b].CreatedAt)
	})
	return jobs, errs
}

// WriteFileAtomic writes data to a temp file in the same folder, fsyncs it
// and renames it over path.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	syncDir(dir)
	return nil
}
