package engine

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lintlabbuild/lint-rdl/internal/policy"
	"github.com/lintlabbuild/lint-rdl/internal/state"
	"github.com/lintlabbuild/lint-rdl/internal/winsec"
)

// partFile wraps the open .part file, its hash and the durable checkpoint.
type partFile struct {
	f          *os.File
	h          hash.Hash
	written    int64 // bytes written (maybe not yet synced)
	checkpoint int64 // bytes known durable and recorded in the journal
}

// openPart opens the job's part file and restores the hash state for the
// recorded checkpoint, truncating anything written after it.
func (m *Manager) openPart(j *state.Job) (*partFile, error) {
	pd, err := m.o.Paths.PartDir(j.Dir)
	if err != nil {
		return nil, err
	}
	want := filepath.Join(pd, j.ID+".part")
	if j.PartPath != want {
		j.PartPath = want
	}
	if err := m.o.Paths.CheckFinalPath(filepath.Join(j.Dir, "x")); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(want, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	p := &partFile{f: f, h: sha256.New()}
	w := j.Written
	if w > st.Size() || w < 0 || !j.Resumable {
		// Part file is shorter than the journal says (lost or replaced), or
		// resume isn't possible: start over.
		w = 0
		j.HashState = nil
	}
	if err := f.Truncate(w); err != nil {
		f.Close()
		return nil, err
	}
	if w > 0 {
		restored := false
		if len(j.HashState) > 0 {
			if u, ok := p.h.(encoding.BinaryUnmarshaler); ok && u.UnmarshalBinary(j.HashState) == nil {
				restored = true
			}
		}
		if !restored {
			// Re-hash the part already on disk.
			p.h.Reset()
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				f.Close()
				return nil, err
			}
			if _, err := io.CopyN(p.h, f, w); err != nil {
				f.Close()
				return nil, fmt.Errorf("re-hashing part file: %w", err)
			}
		}
	}
	if _, err := f.Seek(w, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	p.written, p.checkpoint = w, w
	j.Written = w
	return p, nil
}

// reset discards all partial data.
func (p *partFile) reset() error {
	if err := p.f.Truncate(0); err != nil {
		return err
	}
	if _, err := p.f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	p.h.Reset()
	p.written, p.checkpoint = 0, 0
	return nil
}

// rollback truncates to the last checkpoint (used after a write error).
func (p *partFile) rollback(hs []byte) {
	p.f.Truncate(p.checkpoint)
	p.f.Seek(p.checkpoint, io.SeekStart)
	p.written = p.checkpoint
	if u, ok := p.h.(encoding.BinaryUnmarshaler); ok && hs != nil {
		u.UnmarshalBinary(hs)
	}
}

func hashState(h hash.Hash) []byte {
	if mm, ok := h.(encoding.BinaryMarshaler); ok {
		if b, err := mm.MarshalBinary(); err == nil {
			return b
		}
	}
	return nil
}

// commit copies the working job into the shared job and saves the journal.
func (m *Manager) commit(jr *jobRun, j *state.Job) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	keep := jr.job.State
	*jr.job = *j
	jr.job.State = keep
	jr.job.UpdatedAt = time.Now().UTC()
	jr.written.Store(j.Written)
	return m.o.Journal.Save(jr.job)
}

// checkpointPart fsyncs the part file and records its length and hash
// state in the journal. A crash after this loses nothing before it.
func (m *Manager) checkpointPart(jr *jobRun, j *state.Job, p *partFile) error {
	if err := p.f.Sync(); err != nil {
		return err
	}
	j.Written = p.written
	j.HashState = hashState(p.h)
	if err := m.commit(jr, j); err != nil {
		return err
	}
	p.checkpoint = p.written
	return nil
}

func (m *Manager) snapshot(jr *jobRun) state.Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	return *jr.job
}

func (m *Manager) notice(jr *jobRun, j *state.Job, msg string) {
	j.Notice = msg
	m.mu.Lock()
	jr.job.Notice = msg
	v := m.viewLocked(jr)
	m.mu.Unlock()
	m.emit(Event{Type: EvNotice, Job: v, Message: msg})
}

// attempt makes one HTTP request and streams as much as it can.
func (m *Manager) attempt(ctx context.Context, jr *jobRun) error {
	j := m.snapshot(jr)

	// The save folder must still exist and still be allowed.
	if _, err := os.Stat(j.Dir); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return &attemptError{kind: kindNoDir, err: fmt.Errorf("save folder is gone (drive unplugged?): %s", j.Dir)}
		}
		return err
	}
	if real, err := m.o.Paths.ResolveDir(j.Dir); err != nil {
		return &attemptError{kind: kindPermanent, err: err}
	} else if !strings.EqualFold(real, j.Dir) {
		return permErr("save folder %s now points to %s; refusing", j.Dir, real)
	}

	p, err := m.openPart(&j)
	if err != nil {
		return classify(err)
	}
	defer p.f.Close()
	if err := m.commit(jr, &j); err != nil {
		return err
	}

	remaining := int64(-1)
	if j.ExpectedSize >= 0 {
		remaining = j.ExpectedSize - p.written
	}
	if err := m.o.Disk.Check(j.Dir, j.ExpectedSize, remaining); err != nil {
		if errors.Is(err, policy.ErrDiskSpace) {
			return &attemptError{kind: kindDisk, err: err}
		}
		return permErr("%v", err)
	}

	req, err := newReq(ctx, http.MethodGet, j.URL, m.o.UserAgent)
	if err != nil {
		return permErr("%v", err)
	}
	if m.o.Authorize != nil {
		m.o.Authorize(req)
	}
	ranged := p.written > 0
	if ranged {
		req.Header.Set("Range", "bytes="+strconv.FormatInt(p.written, 10)+"-")
		if isStrongETag(j.ETag) {
			req.Header.Set("If-Range", j.ETag)
		} else if j.LastModified != "" {
			req.Header.Set("If-Range", j.LastModified)
		}
	}
	resp, err := m.client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return classify(err)
	}
	defer resp.Body.Close()
	j.FinalURL = resp.Request.URL.String()

	if err := m.checkStatus(jr, &j, p, resp, ranged); err != nil {
		if ae, ok := err.(*attemptError); ok && ae.reset {
			j.Written, j.HashState = 0, nil
			m.commit(jr, &j)
		}
		if errors.Is(err, errAlreadyComplete) {
			return m.finish(jr, &j, p)
		}
		return err
	}

	body := io.Reader(resp.Body)
	if enc := strings.ToLower(resp.Header.Get("Content-Encoding")); enc != "" && enc != "identity" {
		if enc != "gzip" && enc != "x-gzip" {
			return permErr("server uses unsupported Content-Encoding %q", enc)
		}
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return retryErr("gzip: %v", err)
		}
		defer gz.Close()
		body = gz
		j.Resumable = false
	}
	if err := m.commit(jr, &j); err != nil {
		return err
	}
	if err := m.stream(ctx, jr, &j, p, body); err != nil {
		return err
	}
	return m.finish(jr, &j, p)
}

var errAlreadyComplete = errors.New("already complete")

// checkStatus validates the response and adjusts the part file. On return
// without error, the body should be appended at p.written.
func (m *Manager) checkStatus(jr *jobRun, j *state.Job, p *partFile, resp *http.Response, ranged bool) error {
	h := resp.Header
	newETag, newLM := h.Get("ETag"), h.Get("Last-Modified")
	changed := func() bool {
		if j.ETag != "" && newETag != "" && j.ETag != newETag {
			return true
		}
		if j.ETag == "" && j.LastModified != "" && newLM != "" && j.LastModified != newLM {
			return true
		}
		return false
	}
	restart := func(msg string) error {
		if err := p.reset(); err != nil {
			return err
		}
		j.ETag, j.LastModified = "", ""
		m.notice(jr, j, msg)
		return &attemptError{kind: kindRestart, err: errors.New(msg), reset: true}
	}

	switch code := resp.StatusCode; {
	case code == http.StatusOK:
		if ranged {
			msg := "server ignored the range request; restarting from 0"
			if changed() {
				msg = "file changed on server; restarting from 0"
			}
			if err := p.reset(); err != nil {
				return err
			}
			m.notice(jr, j, msg)
		}
		if err := m.acceptHeaders(j, resp); err != nil {
			return err
		}
		if resp.ContentLength >= 0 && h.Get("Content-Encoding") == "" {
			if j.ExpectedSize >= 0 && resp.ContentLength != j.ExpectedSize {
				return permErr("size mismatch: server says %d bytes, expected %d", resp.ContentLength, j.ExpectedSize)
			}
			j.ExpectedSize = resp.ContentLength
		}
		j.Resumable = resp.ContentLength >= 0
		j.ETag, j.LastModified = newETag, newLM
		if j.ETag == "" && j.LastModified == "" {
			m.notice(jr, j, "server sends no ETag or Last-Modified; resume relies on the size and the final SHA-256")
		}
		return nil

	case code == http.StatusPartialContent:
		if strings.HasPrefix(h.Get("Content-Type"), "multipart/byteranges") {
			j.Resumable = false
			return restart("server sent a multipart range reply (not supported); restarting without ranges")
		}
		if enc := h.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
			j.Resumable = false
			return restart("server compresses ranged replies; restarting without resume")
		}
		cr, err := parseContentRange(h.Get("Content-Range"))
		if err != nil || cr.Unsat {
			j.Resumable = false
			return restart("server sent a broken Content-Range; restarting from 0")
		}
		if cr.Start != p.written {
			j.Resumable = false
			return restart(fmt.Sprintf("server sent bytes from %d, asked for %d; restarting from 0", cr.Start, p.written))
		}
		if changed() || (j.ExpectedSize >= 0 && cr.Total >= 0 && cr.Total != j.ExpectedSize) {
			return restart("file changed on server; restarting from 0")
		}
		if !ranged {
			return retryErr("server sent a partial reply to a full request")
		}
		if err := m.acceptHeaders(j, resp); err != nil {
			return err
		}
		if cr.Total >= 0 && j.ExpectedSize < 0 {
			j.ExpectedSize = cr.Total
		}
		if newETag != "" {
			j.ETag = newETag
		}
		if newLM != "" {
			j.LastModified = newLM
		}
		return nil

	case code == http.StatusRequestedRangeNotSatisfiable:
		cr, _ := parseContentRange(h.Get("Content-Range"))
		total := cr.Total
		if total < 0 {
			total = j.ExpectedSize
		}
		if total >= 0 && total == p.written && !changed() {
			return errAlreadyComplete
		}
		return restart("server says the range is invalid (file shrank or changed); restarting from 0")

	case code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable:
		w := parseRetryAfter(h.Get("Retry-After"), time.Now())
		return &attemptError{kind: kindRetry, wait: w, err: fmt.Errorf("server busy (%d)", code)}

	case code == http.StatusUnauthorized || code == http.StatusForbidden || code == http.StatusGone:
		return &attemptError{kind: kindRetry, auth: true,
			err: fmt.Errorf("access denied (%d); if this was a signed link it expired, re-requesting the original URL", code)}

	case code == http.StatusNotFound:
		return permErr("not found (404)")

	case code == http.StatusRequestTimeout || code >= 500:
		return retryErr("server error %d", code)

	default:
		return permErr("server answered %d %s", code, http.StatusText(code))
	}
}

// acceptHeaders checks content type and picks the file name on the first
// real response.
func (m *Manager) acceptHeaders(j *state.Job, resp *http.Response) error {
	if !j.NameFixed {
		if n := filenameFromDisposition(resp.Header.Get("Content-Disposition")); n != "" {
			if clean := policy.SanitizeFilename(n, ""); clean != "" {
				j.Name = clean
			}
		}
		j.NameFixed = true
	}
	if policy.IsStreamManifest(resp.Header.Get("Content-Type"), j.Name) {
		return permErr(policy.ErrStreamManifest)
	}
	if isHTMLType(resp.Header.Get("Content-Type")) && !wantsHTML(j.Name) {
		return permErr("server sent a web page (text/html) instead of the file; it may be a login or error page")
	}
	if m.o.BlockExtensions == "block" && policy.HasBlockedExtension(j.Name, m.o.BlockedExts) {
		return permErr("%s: files of this type are blocked by config", j.Name)
	}
	return nil
}

// stream copies body to the part file with checkpoints, stall detection,
// speed limiting and disk checks.
func (m *Manager) stream(ctx context.Context, jr *jobRun, j *state.Job, p *partFile, body io.Reader) error {
	// Stall watchdog: if no bytes arrive for StallTimeout, cancel the request.
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var stalled bool
	var smu sync.Mutex
	timer := time.AfterFunc(m.o.StallTimeout, func() {
		smu.Lock()
		stalled = true
		smu.Unlock()
		cancel()
	})
	defer timer.Stop()
	if rc, ok := body.(io.ReadCloser); ok {
		go func() {
			<-sctx.Done()
			rc.Close()
		}()
	}
	isStalled := func() bool {
		smu.Lock()
		defer smu.Unlock()
		return stalled
	}

	buf := make([]byte, 256<<10)
	sinceCheck := int64(0)
	sinceDisk := int64(0)
	lastHS := hashState(p.h)
	winStart, winBytes := time.Now(), int64(0)
	speedT, speedB := time.Now(), p.written

	for {
		n, rerr := body.Read(buf)
		if n > 0 {
			timer.Reset(m.o.StallTimeout)
			if j.ExpectedSize >= 0 && p.written+int64(n) > j.ExpectedSize {
				p.reset()
				j.Written, j.HashState = 0, nil
				m.commit(jr, j)
				return retryErr("server sent more data than expected; restarting")
			}
			if err := m.limiter.wait(sctx, n); err != nil {
				break
			}
			if _, werr := p.f.Write(buf[:n]); werr != nil {
				p.rollback(lastHS)
				if isDiskFull(werr) {
					return &attemptError{kind: kindDisk, err: fmt.Errorf("%w: disk full while writing", policy.ErrDiskSpace)}
				}
				return retryErr("write: %v", werr)
			}
			p.h.Write(buf[:n])
			p.written += int64(n)
			sinceCheck += int64(n)
			sinceDisk += int64(n)
			winBytes += int64(n)
			jr.written.Store(p.written)

			if sinceCheck >= m.o.ChunkSize {
				if err := m.checkpointPart(jr, j, p); err != nil {
					p.rollback(lastHS)
					if isDiskFull(err) {
						return &attemptError{kind: kindDisk, err: fmt.Errorf("%w: disk full while writing", policy.ErrDiskSpace)}
					}
					return retryErr("checkpoint: %v", err)
				}
				lastHS = j.HashState
				sinceCheck = 0
			}
			if j.ExpectedSize < 0 && sinceDisk >= m.o.UnknownSizeStep {
				sinceDisk = 0
				if err := m.o.Disk.Check(j.Dir, -1, -1); err != nil {
					m.checkpointPart(jr, j, p)
					return &attemptError{kind: kindDisk, err: err}
				}
			}
			if now := time.Since(speedT); now >= time.Second {
				m.mu.Lock()
				jr.speed = float64(p.written-speedB) / now.Seconds()
				v := m.viewLocked(jr)
				m.mu.Unlock()
				m.emit(Event{Type: EvProgress, Job: v})
				speedT, speedB = time.Now(), p.written
			}
		}
		if m.o.LowSpeedBytes > 0 {
			if el := time.Since(winStart); el >= m.o.LowSpeedWindow {
				if float64(winBytes)/el.Seconds() < float64(m.o.LowSpeedBytes) {
					m.checkpointPart(jr, j, p)
					return retryErr("speed below %s/s for %s; reconnecting", policy.HumanBytes(m.o.LowSpeedBytes), m.o.LowSpeedWindow)
				}
				winStart, winBytes = time.Now(), 0
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			if err := m.checkpointPart(jr, j, p); err != nil {
				p.rollback(lastHS)
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if isStalled() {
				return retryErr("no data for %s; reconnecting", m.o.StallTimeout)
			}
			return retryErr("connection lost after %s: %v", policy.HumanBytes(p.written), rerr)
		}
	}
	if err := m.checkpointPart(jr, j, p); err != nil {
		p.rollback(lastHS)
		return retryErr("checkpoint: %v", err)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if isStalled() {
		return retryErr("no data for %s; reconnecting", m.o.StallTimeout)
	}
	if j.ExpectedSize >= 0 && p.written < j.ExpectedSize {
		return retryErr("connection closed early at %s of %s", policy.HumanBytes(p.written), policy.HumanBytes(j.ExpectedSize))
	}
	return nil
}

func isDiskFull(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		// ENOSPC on Unix; ERROR_DISK_FULL (112) / ERROR_HANDLE_DISK_FULL (39) on Windows.
		if errno == 28 || errno == 112 || errno == 39 {
			return true
		}
	}
	return strings.Contains(strings.ToLower(err.Error()), "no space left")
}

// finish verifies the file and moves it into place.
func (m *Manager) finish(jr *jobRun, j *state.Job, p *partFile) error {
	m.setState(jr, state.StateVerifying, "")
	if err := p.f.Sync(); err != nil {
		return retryErr("sync: %v", err)
	}
	if j.ExpectedSize >= 0 && p.written != j.ExpectedSize {
		return retryErr("size check failed: have %d, expected %d", p.written, j.ExpectedSize)
	}
	sum := hex.EncodeToString(p.h.Sum(nil))
	if j.ExpectedSHA256 != "" && !strings.EqualFold(sum, j.ExpectedSHA256) {
		p.reset()
		j.Written, j.HashState = 0, nil
		m.commit(jr, j)
		return permErr("SHA-256 mismatch: got %s, expected %s (partial data discarded)", sum, j.ExpectedSHA256)
	}
	p.f.Close()

	// Re-check the destination right before the rename.
	dest, err := policy.ReserveUniqueName(j.Dir, j.Name)
	if err != nil {
		return retryErr("reserve name: %v", err)
	}
	if err := m.o.Paths.CheckFinalPath(dest); err != nil {
		os.Remove(dest)
		return &attemptError{kind: kindPermanent, err: err}
	}
	var rerr error
	for i := 0; i < m.o.RenameRetries; i++ {
		if rerr = os.Rename(j.PartPath, dest); rerr == nil {
			break
		}
		time.Sleep(time.Duration(i+1) * 200 * time.Millisecond) // antivirus may hold the file
	}
	if rerr != nil {
		os.Remove(dest)
		return retryErr("could not move the finished file into place (locked by another program?): %v", rerr)
	}
	os.Chmod(dest, 0o644) // part files are private (0600); finished files are normal
	if err := winsec.WriteMOTW(dest, j.URL, j.FinalURL); err != nil {
		m.notice(jr, j, "could not write Mark of the Web: "+err.Error())
	}
	j.FinalPath = dest
	j.SHA256 = sum
	j.Verified = j.ExpectedSHA256 != ""
	j.HashState = nil
	j.DoneAt = time.Now().UTC()
	j.Error = ""
	m.commit(jr, j)
	m.setState(jr, state.StateDone, "")
	m.audit("download", "", "", j, "done sha256="+sum)
	return nil
}

// Verify recomputes the SHA-256 of a finished job's file.
func (m *Manager) Verify(ctx context.Context, id string) (sum string, match bool, err error) {
	v, err := m.Get(id)
	if err != nil {
		return "", false, err
	}
	if v.State != state.StateDone || v.FinalPath == "" {
		return "", false, fmt.Errorf("job %s is %s, not done", id, v.State)
	}
	if v.Kind == "git" {
		return "", false, fmt.Errorf("%s is a Git repository at commit %s; Git checked every object while cloning (transfer.fsckObjects)", v.FinalPath, v.Commit)
	}
	if err := m.o.Paths.CheckFinalPath(v.FinalPath); err != nil {
		return "", false, err
	}
	sum, err = HashFile(ctx, v.FinalPath)
	if err != nil {
		return "", false, err
	}
	want := v.ExpectedSHA256
	if want == "" {
		want = v.SHA256
	}
	return sum, strings.EqualFold(sum, want), nil
}

// HashFile computes a file's SHA-256 (the hash only; content never leaves).
func HashFile(ctx context.Context, path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, 1<<20)
	for {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		n, err := f.Read(buf)
		h.Write(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// rateLimiter is a simple global token bucket.
type rateLimiter struct {
	mu     sync.Mutex
	rate   int64
	tokens float64
	last   time.Time
}

func newRateLimiter(rate int64) *rateLimiter {
	return &rateLimiter{rate: rate, last: time.Now()}
}

// SetLimit changes the global speed cap (0 = off).
func (m *Manager) SetLimit(bytesPerSec int64) {
	m.limiter.mu.Lock()
	m.limiter.rate = bytesPerSec
	m.limiter.mu.Unlock()
}

func (l *rateLimiter) wait(ctx context.Context, n int) error {
	for {
		l.mu.Lock()
		if l.rate <= 0 {
			l.mu.Unlock()
			return nil
		}
		now := time.Now()
		l.tokens += now.Sub(l.last).Seconds() * float64(l.rate)
		if max := float64(l.rate); l.tokens > max {
			l.tokens = max
		}
		l.last = now
		if l.tokens >= float64(n) || l.tokens >= float64(l.rate) {
			l.tokens -= float64(n)
			l.mu.Unlock()
			return nil
		}
		need := (float64(n) - l.tokens) / float64(l.rate)
		l.mu.Unlock()
		t := time.NewTimer(time.Duration(need * float64(time.Second)))
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		}
	}
}
