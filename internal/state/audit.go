package state

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEntry is one line of the audit log.
type AuditEntry struct {
	Time     time.Time `json:"time"`
	Identity string    `json:"identity"`
	Via      string    `json:"via"`
	Command  string    `json:"command"`
	URL      string    `json:"url,omitempty"`
	Dest     string    `json:"dest,omitempty"`
	JobID    string    `json:"job,omitempty"`
	Result   string    `json:"result"`
}

// Audit is an append-only JSON-lines log with size-based rotation.
type Audit struct {
	path    string
	maxSize int64
	keep    int
	mu      sync.Mutex
}

// OpenAudit opens the audit log at path. maxSize <= 0 means 10 MB.
func OpenAudit(path string, maxSize int64) (*Audit, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if maxSize <= 0 {
		maxSize = 10 << 20
	}
	return &Audit{path: path, maxSize: maxSize, keep: 5}, nil
}

// Path returns the current log file.
func (a *Audit) Path() string { return a.path }

// Log appends an entry. Errors are returned but callers usually only warn.
func (a *Audit) Log(e AuditEntry) error {
	if a == nil {
		return nil
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if fi, err := os.Stat(a.path); err == nil && fi.Size()+int64(len(line)) > a.maxSize {
		a.rotate()
	}
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

func (a *Audit) rotate() {
	os.Remove(fmt.Sprintf("%s.%d", a.path, a.keep))
	for i := a.keep - 1; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", a.path, i), fmt.Sprintf("%s.%d", a.path, i+1))
	}
	os.Rename(a.path, a.path+".1")
}

// Tail returns the last n entries of the current log file.
func (a *Audit) Tail(n int) ([]AuditEntry, error) {
	f, err := os.Open(a.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var all []AuditEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		var e AuditEntry
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			all = append(all, e)
		}
	}
	if n > 0 && len(all) > n {
		all = all[len(all)-n:]
	}
	return all, sc.Err()
}
