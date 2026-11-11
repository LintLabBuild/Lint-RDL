package engine

import (
	"fmt"
	"strings"
	"time"

	"github.com/lintlabbuild/lint-rdl/internal/policy"
	"github.com/lintlabbuild/lint-rdl/internal/state"
)

// Resume modes: what to do when a server can't continue a download
// where it stopped (it ignores Range and sends the file from byte 0).
//
// When the server *can* resume, every mode asks only for the missing
// bytes.
const (
	// ModeAuto is the default. Today it behaves like ModeRatchet.
	ModeAuto = "auto"
	// ModeRatchet keeps the partial file. When the server re-sends from 0,
	// the bytes rdl already has are read without being saved, hashed in
	// memory and compared with the saved SHA-256 state: same file → keep
	// writing after them; different → the file changed, restart. Verified
	// bytes are never thrown away, so a later attempt that reaches a server
	// (or CDN edge, or relinked URL) that does support ranges continues
	// from the best point. It costs the re-sent bandwidth.
	ModeRatchet = "ratchet"
	// ModeMissingOnly never re-downloads bytes rdl already has. If the
	// server can't resume, the job stops (partial kept) until the user
	// relinks, retries with another mode, or a mirror is added. For
	// metered data plans.
	ModeMissingOnly = "missing-only"
	// ModeRestart is all-or-nothing: wipe the partial file and download
	// again from zero.
	ModeRestart = "restart"
)

// ResumeModes lists the valid modes.
var ResumeModes = []string{ModeAuto, ModeRatchet, ModeMissingOnly, ModeRestart}

// ValidResumeMode checks a mode name.
func ValidResumeMode(m string) error {
	for _, v := range ResumeModes {
		if m == v {
			return nil
		}
	}
	return fmt.Errorf("unknown resume mode %q (use %s)", m, strings.Join(ResumeModes, ", "))
}

// effectiveMode resolves auto and the manager default.
func (m *Manager) effectiveMode(j *state.Job) string {
	mode := j.ResumeMode
	if mode == "" {
		mode = m.o.ResumeMode
	}
	if mode == "" || mode == ModeAuto {
		return ModeRatchet
	}
	return mode
}

func missingOnlyStop(j *state.Job, have int64) error {
	return permErr("the server can't continue from %s; resume mode is missing-only, so rdl stopped instead of downloading %s again (partial file kept). "+
		"Continue with: rdl retry %s --resume-mode ratchet, or give a new link: rdl relink %s <url>",
		policy.HumanBytes(have), policy.HumanBytes(have), j.ID, j.ID)
}

// SetResumeMode changes a job's resume mode (not while it runs).
func (m *Manager) SetResumeMode(id, mode string) error {
	if err := ValidResumeMode(mode); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	jr, ok := m.jobs[id]
	if !ok {
		return ErrNotFound
	}
	if jr.running {
		return fmt.Errorf("job %s is running; pause it first", id)
	}
	jr.job.ResumeMode = mode
	return m.o.Journal.Save(jr.job)
}

// Relink gives a failed or paused job a new link to the same file (for
// expired temporary links). The partial file is kept. If the expected
// SHA-256 is known, the download resumes with a range request and the
// final hash proves it was the same file; otherwise the saved part is
// first verified against the new server (ratchet) before anything is
// appended.
//
// sha256 (optional) sets the expected hash if the job had none, which lets
// the new link send only the missing bytes.
func (m *Manager) Relink(id, rawURL, sha256 string) error {
	u, err := m.o.URLPolicy.CheckRawURL(rawURL)
	if err != nil {
		return err
	}
	sha256 = strings.ToLower(strings.TrimSpace(sha256))
	if sha256 != "" && !isHexSHA256(sha256) {
		return fmt.Errorf("--sha256 must be 64 hex characters")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	jr, ok := m.jobs[id]
	if !ok {
		return ErrNotFound
	}
	if jr.running {
		return fmt.Errorf("job %s is running; pause it first", id)
	}
	if jr.job.Kind == "git" || jr.job.State == state.StateDone || jr.job.State == state.StateCancelled {
		return fmt.Errorf("job %s can't be relinked (%s)", id, jr.job.State)
	}
	j := jr.job
	if sha256 != "" {
		if j.ExpectedSHA256 != "" && j.ExpectedSHA256 != sha256 {
			return fmt.Errorf("job %s already expects SHA-256 %s", id, j.ExpectedSHA256)
		}
		j.ExpectedSHA256 = sha256
	}
	j.URL = u.String()
	j.FinalURL = ""
	j.ETag, j.LastModified = "", ""
	j.RangeBroken = false
	j.VerifyPrefix = j.Written > 0 && j.ExpectedSHA256 == ""
	j.Attempts = 0
	j.Error = ""
	j.Notice = "relinked to a new URL"
	j.State = state.StateQueued
	j.UpdatedAt = time.Now().UTC()
	jr.authFails = 0
	if err := m.o.Journal.Save(j); err != nil {
		return err
	}
	if m.started {
		m.launchLocked(jr)
	}
	m.notifyLocked()
	return nil
}
