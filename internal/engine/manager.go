// Package engine downloads files: probe, queue, workers, resume, verify,
// and the final move into place. It never runs, opens or sends out what it
// downloads; only names, sizes, progress and hashes leave it.
package engine

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lintlabbuild/lint-rdl/internal/gitdl"
	"github.com/lintlabbuild/lint-rdl/internal/policy"
	"github.com/lintlabbuild/lint-rdl/internal/power"
	"github.com/lintlabbuild/lint-rdl/internal/state"
)

// DefaultUserAgent identifies rdl to servers.
const DefaultUserAgent = "rdl/0.1 (+resumable download manager)"

// Options configures a Manager.
type Options struct {
	URLPolicy *policy.URLPolicy
	Paths     *policy.PathPolicy
	Disk      *policy.DiskGuard
	Journal   *state.Journal
	Audit     *state.Audit // may be nil
	// Client defaults to URLPolicy.NewClient.
	Client *http.Client

	MaxParallel     int           // default 3
	ChunkSize       int64         // fsync + journal interval, default 8 MB
	UnknownSizeStep int64         // disk re-check interval for unknown sizes, default 256 MB
	StallTimeout    time.Duration // default 2 min
	LowSpeedBytes   int64         // bytes/s; 0 = off
	LowSpeedWindow  time.Duration // default 60 s
	SpeedLimit      int64         // global bytes/s; 0 = off
	Backoff         []time.Duration
	RetryAfterCap   time.Duration // default 1 h
	MaxAuthRetries  int           // consecutive 401/403/410 before failing, default 5
	MaxAttempts     int           // 0 = retry forever
	// ResumeMode is the default for jobs that don't set one: auto,
	// ratchet, missing-only or restart (see resume.go).
	ResumeMode      string
	DiskPollEvery   time.Duration // how often paused-disk jobs re-check, default 30 s
	RenameRetries   int           // default 10
	BlockExtensions string        // off | warn | block
	BlockedExts     []string
	UserAgent       string
	// GitPath is the git executable ("" = Git not installed). Repository
	// links on GitHosts are cloned with it.
	GitPath        string
	GitHosts       []string
	GitFullHistory bool
	// Authorize may add credentials to the first request of each attempt
	// (e.g. a Hugging Face token for huggingface.co only). Go drops the
	// Authorization header on redirects to other hosts.
	Authorize func(req *http.Request)
	// OnEvent receives job events (progress is throttled to ~1/s per job).
	OnEvent func(Event)
}

// DefaultBackoff is 5s, 15s, 30s, 1m, then every 5m (spec §5.4).
var DefaultBackoff = []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second, time.Minute, 5 * time.Minute}

// Event types.
const (
	EvQueued   = "queued"
	EvState    = "state"
	EvProgress = "progress"
	EvDone     = "done"
	EvFailed   = "failed"
	EvNotice   = "notice"
)

// Event reports a change to one job.
type Event struct {
	Type    string  `json:"type"`
	Job     JobView `json:"job"`
	Message string  `json:"message,omitempty"`
}

// JobView is a job plus live numbers, safe to show any interface.
type JobView struct {
	state.Job
	Downloaded int64     `json:"downloaded"`
	Speed      float64   `json:"speed"`         // bytes/s
	ETA        float64   `json:"eta,omitempty"` // seconds
	NextRetry  time.Time `json:"next_retry,omitempty"`
	// CatchingUp > 0 while the ratchet re-reads (and verifies) the part
	// already saved, without writing it.
	CatchingUp int64 `json:"catching_up,omitempty"`
}

// Progress returns 0..1, or -1 if the size is unknown.
func (v JobView) Progress() float64 {
	if v.ExpectedSize <= 0 {
		return -1
	}
	return float64(v.Downloaded) / float64(v.ExpectedSize)
}

type jobRun struct {
	job       *state.Job
	written   atomic.Int64
	catchup   atomic.Int64 // ratchet: bytes re-read so far (not written)
	speed     float64
	nextRetry time.Time
	running   bool
	cancel    context.CancelFunc
	pauseReq  bool
	cancelReq bool
	authFails int
}

// Manager runs the queue.
type Manager struct {
	o       Options
	client  *http.Client
	limiter *rateLimiter
	awake   power.Awake

	mu      sync.Mutex
	jobs    map[string]*jobRun
	changed chan struct{}
	sem     chan struct{}
	ctx     context.Context
	stop    context.CancelFunc
	wg      sync.WaitGroup
	started bool
}

// ErrDuplicate is returned by Add when the same URL is already queued.
var ErrDuplicate = errors.New("this URL is already in the queue")

// ErrNotFound is returned for unknown job ids.
var ErrNotFound = errors.New("no such job")

// New creates a manager and loads unfinished jobs from the journal.
func New(o Options) (*Manager, error) {
	if o.URLPolicy == nil || o.Paths == nil || o.Journal == nil {
		return nil, errors.New("engine: URLPolicy, Paths and Journal are required")
	}
	if o.Disk == nil {
		o.Disk = &policy.DiskGuard{MinFree: 10 << 30}
	}
	if o.MaxParallel <= 0 {
		o.MaxParallel = 3
	}
	if o.ChunkSize <= 0 {
		o.ChunkSize = 8 << 20
	}
	if o.UnknownSizeStep <= 0 {
		o.UnknownSizeStep = 256 << 20
	}
	if o.StallTimeout <= 0 {
		o.StallTimeout = 2 * time.Minute
	}
	if o.LowSpeedWindow <= 0 {
		o.LowSpeedWindow = time.Minute
	}
	if len(o.Backoff) == 0 {
		o.Backoff = DefaultBackoff
	}
	if o.RetryAfterCap <= 0 {
		o.RetryAfterCap = time.Hour
	}
	if o.MaxAuthRetries <= 0 {
		o.MaxAuthRetries = 5
	}
	if o.DiskPollEvery <= 0 {
		o.DiskPollEvery = 30 * time.Second
	}
	if o.RenameRetries <= 0 {
		o.RenameRetries = 10
	}
	if o.UserAgent == "" {
		o.UserAgent = DefaultUserAgent
	}
	if o.BlockedExts == nil {
		o.BlockedExts = policy.DefaultBlockedExtensions
	}
	m := &Manager{
		o:       o,
		jobs:    map[string]*jobRun{},
		changed: make(chan struct{}),
		sem:     make(chan struct{}, o.MaxParallel),
		limiter: newRateLimiter(o.SpeedLimit),
	}
	m.client = o.Client
	if m.client == nil {
		m.client = o.URLPolicy.NewClient(policy.ClientOptions{})
	}
	m.ctx, m.stop = context.WithCancel(context.Background())
	jobs, _ := o.Journal.All()
	for _, j := range jobs {
		jr := &jobRun{job: j}
		jr.written.Store(j.Written)
		switch j.State {
		case state.StateRunning, state.StateRetrying, state.StateVerifying, state.StatePausedDisk, state.StatePausedNoDir:
			j.State = state.StateQueued
		}
		m.jobs[j.ID] = jr
	}
	return m, nil
}

// Start launches queued jobs. Jobs added later start automatically.
func (m *Manager) Start() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.started {
		return
	}
	m.started = true
	for _, jr := range m.sortedLocked() {
		if jr.job.State == state.StateQueued {
			m.launchLocked(jr)
		}
	}
}

// Close stops all work. Jobs stay in the journal and resume next time.
func (m *Manager) Close() {
	m.stop()
	m.wg.Wait()
	policy.CloseIdle(m.client)
}

// Rescan loads jobs that another rdl process added to the journal since
// this manager started (e.g. `rdl add` while `rdl run` is active).
func (m *Manager) Rescan() int {
	jobs, _ := m.o.Journal.All()
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, j := range jobs {
		if _, ok := m.jobs[j.ID]; ok || j.State != state.StateQueued {
			continue
		}
		jr := &jobRun{job: j}
		jr.written.Store(j.Written)
		m.jobs[j.ID] = jr
		if m.started {
			m.launchLocked(jr)
		}
		n++
	}
	if n > 0 {
		m.notifyLocked()
	}
	return n
}

// FindByURL returns the newest job for url that is not cancelled.
func (m *Manager) FindByURL(url string) (JobView, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var best *jobRun
	for _, jr := range m.jobs {
		if jr.job.URL == url && jr.job.State != state.StateCancelled {
			if best == nil || jr.job.CreatedAt.After(best.job.CreatedAt) {
				best = jr
			}
		}
	}
	if best == nil {
		return JobView{}, false
	}
	return m.viewLocked(best), true
}

// Client returns the policy-checked HTTP client.
func (m *Manager) Client() *http.Client { return m.client }

func (m *Manager) sortedLocked() []*jobRun {
	out := make([]*jobRun, 0, len(m.jobs))
	for _, jr := range m.jobs {
		out = append(out, jr)
	}
	sort.Slice(out, func(a, b int) bool {
		ja, jb := out[a].job, out[b].job
		if ja.CreatedAt.Equal(jb.CreatedAt) {
			return ja.ID < jb.ID
		}
		return ja.CreatedAt.Before(jb.CreatedAt)
	})
	return out
}

func newID() string {
	const alphabet = "abcdefghijkmnpqrstuvwxyz23456789"
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

// AddRequest describes a new download.
type AddRequest struct {
	URL            string
	Dir            string // folder (absolute or relative to the default root); empty = default
	Name           string // optional file name
	SHA256         string // optional expected hash
	ExpectedSize   int64  // optional; <= 0 unknown
	AllowDuplicate bool
	Owner          string
	Via            string
	ResumeMode     string // optional per-job resume mode
}

// Add validates and queues a download. Policy checks happen here and
// again right before every write.
func (m *Manager) Add(r AddRequest) (*state.Job, error) {
	u, err := m.o.URLPolicy.CheckRawURL(r.URL)
	if err != nil {
		return nil, err
	}
	if raw, ok := gitdl.RewriteBlob(u); ok {
		if u, err = m.o.URLPolicy.CheckRawURL(raw.String()); err != nil {
			return nil, err
		}
	}
	repo, isRepo := gitdl.Detect(u, m.o.GitHosts)
	if isRepo && m.o.GitPath == "" {
		return nil, gitdl.ErrNoGit
	}
	dir, err := m.o.Paths.ResolveDir(r.Dir)
	if err != nil {
		return nil, err
	}
	sha := strings.ToLower(strings.TrimSpace(r.SHA256))
	if sha != "" && !isHexSHA256(sha) {
		return nil, fmt.Errorf("--sha256 must be 64 hex characters")
	}
	name := ""
	fixed := false
	if strings.TrimSpace(r.Name) != "" {
		name = policy.SanitizeFilename(r.Name, "")
		if name == "" {
			return nil, fmt.Errorf("invalid file name %q", r.Name)
		}
		fixed = true
	}
	id := newID()
	if name == "" {
		name = policy.SanitizeFilename(filenameFromURL(u), "download-"+id)
	}
	if m.o.BlockExtensions == "block" && policy.HasBlockedExtension(name, m.o.BlockedExts) {
		return nil, fmt.Errorf("%w: files of this type (%s) are blocked by config", policy.ErrPathBlocked, filepath.Ext(name))
	}
	size := r.ExpectedSize
	if size <= 0 {
		size = -1
	}
	if size > policy.FAT32MaxFile {
		if err := m.o.Disk.Check(dir, size, 0); err != nil && !errors.Is(err, policy.ErrDiskSpace) {
			return nil, err
		}
	}
	if r.ResumeMode != "" {
		if err := ValidResumeMode(r.ResumeMode); err != nil {
			return nil, err
		}
	}
	now := time.Now().UTC()
	job := &state.Job{
		ResumeMode: r.ResumeMode,
		ID:         id, URL: u.String(), Dir: dir, Name: name, NameFixed: fixed,
		Owner: r.Owner, Via: r.Via, CreatedAt: now, UpdatedAt: now,
		ExpectedSize: size, ExpectedSHA256: sha, State: state.StateQueued, Resumable: true,
	}
	if isRepo {
		job.Kind = "git"
		job.GitURL = repo.CloneURL
		job.GitRef = repo.Ref
		job.GitFull = m.o.GitFullHistory
		job.Resumable = false
		job.ExpectedSHA256 = ""
		if !fixed {
			job.Name = policy.SanitizeFilename(repo.Name, "repo-"+id)
		}
	}
	m.mu.Lock()
	if !r.AllowDuplicate {
		for _, jr := range m.jobs {
			if jr.job.URL == job.URL && jr.job.State != state.StateCancelled && jr.job.State != state.StateFailed {
				m.mu.Unlock()
				return nil, fmt.Errorf("%w (job %s, %s)", ErrDuplicate, jr.job.ID, jr.job.State)
			}
		}
	}
	if err := m.o.Journal.Save(job); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	jr := &jobRun{job: job}
	m.jobs[id] = jr
	if m.started {
		m.launchLocked(jr)
	}
	m.notifyLocked()
	view := m.viewLocked(jr)
	cp := *job
	m.mu.Unlock()
	m.audit("add", r.Owner, r.Via, &cp, "queued")
	m.emit(Event{Type: EvQueued, Job: view})
	return &cp, nil
}

func (m *Manager) launchLocked(jr *jobRun) {
	if jr.running {
		return
	}
	jr.running = true
	jr.pauseReq, jr.cancelReq = false, false
	ctx, cancel := context.WithCancel(m.ctx)
	jr.cancel = cancel
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		defer cancel()
		m.runLoop(ctx, jr)
	}()
}

// notifyLocked wakes everyone blocked in Wait.
func (m *Manager) notifyLocked() {
	close(m.changed)
	m.changed = make(chan struct{})
}

func (m *Manager) viewLocked(jr *jobRun) JobView {
	v := JobView{Job: *jr.job, Downloaded: jr.written.Load(), Speed: jr.speed, NextRetry: jr.nextRetry, CatchingUp: jr.catchup.Load()}
	v.HashState = nil
	if v.Speed > 0 && v.ExpectedSize > 0 && v.Downloaded < v.ExpectedSize {
		v.ETA = float64(v.ExpectedSize-v.Downloaded) / v.Speed
	}
	if v.State.Terminal() {
		v.Speed = 0
	}
	return v
}

func (m *Manager) emit(ev Event) {
	if m.o.OnEvent != nil {
		m.o.OnEvent(ev)
	}
}

func (m *Manager) auditJob(jr *jobRun, cmd, result string) {
	m.mu.Lock()
	cp := *jr.job
	m.mu.Unlock()
	m.audit(cmd, "", "", &cp, result)
}

func (m *Manager) audit(cmd, who, via string, j *state.Job, result string) {
	if m.o.Audit == nil {
		return
	}
	if who == "" {
		who = j.Owner
	}
	if via == "" {
		via = j.Via
	}
	dest := filepath.Join(j.Dir, j.Name)
	if j.FinalPath != "" {
		dest = j.FinalPath
	}
	m.o.Audit.Log(state.AuditEntry{Identity: who, Via: via, Command: cmd, URL: j.URL, Dest: dest, JobID: j.ID, Result: result})
}

// setState changes state, saves the journal and notifies.
func (m *Manager) setState(jr *jobRun, s state.JobState, msg string) {
	m.mu.Lock()
	jr.job.State = s
	if s == state.StateFailed || s == state.StatePausedDisk || s == state.StatePausedNoDir || s == state.StateRetrying {
		jr.job.Error = msg
	} else if s == state.StateRunning || s == state.StateQueued || s == state.StateDone {
		jr.job.Error = ""
	}
	jr.job.UpdatedAt = time.Now().UTC()
	m.o.Journal.Save(jr.job)
	m.notifyLocked()
	v := m.viewLocked(jr)
	m.mu.Unlock()
	t := EvState
	switch s {
	case state.StateDone:
		t = EvDone
	case state.StateFailed:
		t = EvFailed
	}
	m.emit(Event{Type: t, Job: v, Message: msg})
}

// List returns all jobs, oldest first.
func (m *Manager) List() []JobView {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []JobView
	for _, jr := range m.sortedLocked() {
		out = append(out, m.viewLocked(jr))
	}
	return out
}

// Get returns one job.
func (m *Manager) Get(id string) (JobView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	jr, ok := m.jobs[id]
	if !ok {
		return JobView{}, ErrNotFound
	}
	return m.viewLocked(jr), nil
}

// Pause stops a job; it keeps its partial data.
func (m *Manager) Pause(id string) error {
	m.mu.Lock()
	jr, ok := m.jobs[id]
	if !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	if jr.job.State.Terminal() {
		m.mu.Unlock()
		return fmt.Errorf("job %s is %s", id, jr.job.State)
	}
	if jr.running {
		jr.pauseReq = true
		jr.cancel()
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()
	m.setState(jr, state.StatePaused, "")
	return nil
}

// Resume continues a paused job.
func (m *Manager) Resume(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	jr, ok := m.jobs[id]
	if !ok {
		return ErrNotFound
	}
	if jr.running {
		return nil
	}
	if jr.job.State != state.StatePaused && jr.job.State != state.StateQueued {
		return fmt.Errorf("job %s is %s; use retry for failed jobs", id, jr.job.State)
	}
	jr.job.State = state.StateQueued
	m.o.Journal.Save(jr.job)
	if m.started {
		m.launchLocked(jr)
	}
	m.notifyLocked()
	return nil
}

// Retry restarts a failed job (keeping valid partial data).
func (m *Manager) Retry(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	jr, ok := m.jobs[id]
	if !ok {
		return ErrNotFound
	}
	if jr.job.State != state.StateFailed && jr.job.State != state.StatePaused && jr.job.State != state.StateQueued {
		return fmt.Errorf("job %s is %s", id, jr.job.State)
	}
	if jr.running {
		return nil
	}
	jr.job.State = state.StateQueued
	jr.job.Attempts = 0
	jr.job.Error = ""
	jr.authFails = 0
	m.o.Journal.Save(jr.job)
	if m.started {
		m.launchLocked(jr)
	}
	m.notifyLocked()
	return nil
}

// Cancel stops a job and deletes its partial file.
func (m *Manager) Cancel(id string) error {
	m.mu.Lock()
	jr, ok := m.jobs[id]
	if !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	if jr.job.State == state.StateDone || jr.job.State == state.StateCancelled {
		m.mu.Unlock()
		return fmt.Errorf("job %s is %s", id, jr.job.State)
	}
	if jr.running {
		jr.cancelReq = true
		jr.cancel()
		m.mu.Unlock()
		return nil
	}
	m.mu.Unlock()
	m.finishCancel(jr)
	return nil
}

func (m *Manager) finishCancel(jr *jobRun) {
	m.mu.Lock()
	part := jr.job.PartPath
	jr.job.Written = 0
	jr.job.HashState = nil
	jr.written.Store(0)
	m.mu.Unlock()
	if part != "" {
		os.RemoveAll(part)
	}
	m.setState(jr, state.StateCancelled, "")
	m.auditJob(jr, "cancel", "cancelled")
}

// Remove forgets a finished, failed or cancelled job (the downloaded file
// itself is never touched).
func (m *Manager) Remove(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	jr, ok := m.jobs[id]
	if !ok {
		return ErrNotFound
	}
	if !jr.job.State.Terminal() {
		return fmt.Errorf("job %s is still %s; cancel it first", id, jr.job.State)
	}
	if jr.job.PartPath != "" && jr.job.State != state.StateDone {
		os.RemoveAll(jr.job.PartPath)
	}
	delete(m.jobs, id)
	m.notifyLocked()
	return m.o.Journal.Delete(id)
}

// Wait blocks until every listed job (all jobs if ids is empty) is done,
// failed, cancelled or paused by the user, or until ctx ends. It returns
// the final views either way.
func (m *Manager) Wait(ctx context.Context, ids ...string) ([]JobView, error) {
	for {
		m.mu.Lock()
		ch := m.changed
		var views []JobView
		settled := true
		if len(ids) == 0 {
			for _, jr := range m.sortedLocked() {
				views = append(views, m.viewLocked(jr))
			}
		} else {
			for _, id := range ids {
				jr, ok := m.jobs[id]
				if !ok {
					m.mu.Unlock()
					return nil, fmt.Errorf("%w: %s", ErrNotFound, id)
				}
				views = append(views, m.viewLocked(jr))
			}
		}
		for _, v := range views {
			if !v.State.Terminal() && v.State != state.StatePaused {
				settled = false
			}
		}
		m.mu.Unlock()
		if settled {
			return views, nil
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return views, ctx.Err()
		}
	}
}

// Subscribe returns a channel closed on the next change (for polling UIs).
func (m *Manager) Subscribe() <-chan struct{} {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.changed
}

// runLoop drives one job through attempts, back-off and pauses.
func (m *Manager) runLoop(ctx context.Context, jr *jobRun) {
	defer func() {
		m.mu.Lock()
		jr.running = false
		jr.speed = 0
		m.notifyLocked()
		m.mu.Unlock()
	}()
	for {
		if m.checkStop(jr) {
			return
		}
		// Acquire a worker slot.
		select {
		case m.sem <- struct{}{}:
		case <-ctx.Done():
			m.checkStop(jr)
			return
		}
		m.awake.Acquire()
		m.setState(jr, state.StateRunning, "")
		before := jr.written.Load()
		var err error
		if m.snapshot(jr).Kind == "git" {
			err = m.attemptGit(ctx, jr)
		} else {
			err = m.attempt(ctx, jr)
		}
		progressed := jr.written.Load() > before
		m.awake.Release()
		<-m.sem

		if err == nil {
			return // finished; state set by finish
		}
		if m.checkStop(jr) {
			return
		}
		if m.ctx.Err() != nil {
			return // manager shutting down; journal keeps the job
		}
		ae := classify(err)
		m.mu.Lock()
		if progressed {
			// The connection worked for a while: a drop after progress is not
			// a run of failures, so the back-off starts again from 5 s.
			jr.job.Attempts = 0
		}
		jr.job.Attempts++
		attempts := jr.job.Attempts
		if ae.auth {
			jr.authFails++
		} else {
			jr.authFails = 0
		}
		authFails := jr.authFails
		m.mu.Unlock()

		var wait time.Duration
		switch ae.kind {
		case kindPermanent:
			m.setState(jr, state.StateFailed, ae.Error())
			m.auditJob(jr, "download", "failed: "+ae.Error())
			return
		case kindDisk:
			m.setState(jr, state.StatePausedDisk, ae.Error())
			wait = m.o.DiskPollEvery
		case kindNoDir:
			m.setState(jr, state.StatePausedNoDir, ae.Error())
			wait = m.o.DiskPollEvery
		case kindRestart:
			continue
		default:
			if ae.auth && authFails >= m.o.MaxAuthRetries {
				m.setState(jr, state.StateFailed, ae.Error())
				m.auditJob(jr, "download", "failed: "+ae.Error())
				return
			}
			if m.o.MaxAttempts > 0 && attempts >= m.o.MaxAttempts {
				m.setState(jr, state.StateFailed, fmt.Sprintf("gave up after %d attempts: %v", attempts, ae))
				return
			}
			wait = m.o.Backoff[min(attempts-1, len(m.o.Backoff)-1)]
			if ae.wait > 0 {
				wait = min(ae.wait, m.o.RetryAfterCap)
			}
			m.mu.Lock()
			jr.nextRetry = time.Now().Add(wait)
			m.mu.Unlock()
			m.setState(jr, state.StateRetrying, fmt.Sprintf("%v (retry in %s)", ae, wait.Round(time.Second)))
		}
		t := time.NewTimer(wait)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			m.checkStop(jr)
			return
		}
		m.mu.Lock()
		jr.nextRetry = time.Time{}
		m.mu.Unlock()
	}
}

// checkStop handles pending pause/cancel requests. It returns true if the
// loop must end.
func (m *Manager) checkStop(jr *jobRun) bool {
	m.mu.Lock()
	pause, cancel := jr.pauseReq, jr.cancelReq
	m.mu.Unlock()
	switch {
	case cancel:
		m.finishCancel(jr)
		return true
	case pause:
		m.setState(jr, state.StatePaused, "")
		return true
	}
	return false
}
