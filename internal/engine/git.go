package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lintlabbuild/lint-rdl/internal/gitdl"
	"github.com/lintlabbuild/lint-rdl/internal/policy"
	"github.com/lintlabbuild/lint-rdl/internal/state"
	"github.com/lintlabbuild/lint-rdl/internal/winsec"
)

// attemptGit clones a repository with the user's Git. Clones can't be
// resumed: an interrupted clone is removed and started again.
func (m *Manager) attemptGit(ctx context.Context, jr *jobRun) error {
	j := m.snapshot(jr)
	if m.o.GitPath == "" {
		return permErr("%v", gitdl.ErrNoGit)
	}
	if _, err := os.Stat(j.Dir); err != nil {
		return &attemptError{kind: kindNoDir, err: fmt.Errorf("save folder is gone (drive unplugged?): %s", j.Dir)}
	}
	if real, err := m.o.Paths.ResolveDir(j.Dir); err != nil {
		return &attemptError{kind: kindPermanent, err: err}
	} else if !strings.EqualFold(real, j.Dir) {
		return permErr("save folder %s now points to %s; refusing", j.Dir, real)
	}
	pd, err := m.o.Paths.PartDir(j.Dir)
	if err != nil {
		return classify(err)
	}
	empty := filepath.Join(pd, "empty")
	os.MkdirAll(empty, 0o700)
	tmp := filepath.Join(pd, j.ID+".git")
	os.RemoveAll(tmp) // leftovers of an interrupted clone
	j.PartPath = tmp
	j.Written = 0
	if err := m.commit(jr, &j); err != nil {
		return err
	}
	if err := m.o.Disk.Check(j.Dir, -1, -1); err != nil {
		if errors.Is(err, policy.ErrDiskSpace) {
			return &attemptError{kind: kindDisk, err: err}
		}
		return permErr("%v", err)
	}

	speedT, speedB := time.Now(), int64(0)
	commit, err := gitdl.Clone(ctx, gitdl.CloneOptions{
		Git: m.o.GitPath, URL: j.GitURL, Ref: j.GitRef, FullHistory: j.GitFull,
		Dest: tmp, EmptyDir: empty,
		Progress: func(pct int, b int64) {
			jr.written.Store(b)
			m.mu.Lock()
			if pct > 0 && b > 0 {
				jr.job.ExpectedSize = b * 100 / int64(pct)
			}
			if el := time.Since(speedT); el >= time.Second {
				jr.speed = float64(b-speedB) / el.Seconds()
				speedT, speedB = time.Now(), b
			}
			v := m.viewLocked(jr)
			m.mu.Unlock()
			m.emit(Event{Type: EvProgress, Job: v})
		},
	})
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if errors.Is(err, gitdl.ErrPermanent) || errors.Is(err, gitdl.ErrNoGit) {
			return permErr("%v", err)
		}
		return retryErr("%v", err)
	}

	m.setState(jr, state.StateVerifying, "")
	dest, err := reserveDirName(j.Dir, j.Name)
	if err != nil {
		os.RemoveAll(tmp)
		return retryErr("%v", err)
	}
	if err := m.o.Paths.CheckFinalPath(filepath.Join(dest, "x")); err != nil {
		os.RemoveAll(tmp)
		os.Remove(dest)
		return &attemptError{kind: kindPermanent, err: err}
	}
	var rerr error
	for i := 0; i < m.o.RenameRetries; i++ {
		os.Remove(dest) // the empty placeholder (Windows can't rename over a folder)
		if rerr = os.Rename(tmp, dest); rerr == nil {
			break
		}
		time.Sleep(time.Duration(i+1) * 200 * time.Millisecond)
	}
	if rerr != nil {
		return retryErr("could not move the repository into place: %v", rerr)
	}
	if n, _ := winsec.MarkTree(dest, j.URL, 200000); n > 0 {
		_ = n
	}
	files, size := gitdl.CountFiles(dest)
	j = m.snapshot(jr)
	j.FinalPath, j.Commit, j.FileCount = dest, commit, files
	j.ExpectedSize, j.Written = size, size
	j.DoneAt = time.Now().UTC()
	j.Error = ""
	m.commit(jr, &j)
	m.setState(jr, state.StateDone, "")
	m.audit("download", "", "", &j, "done git commit="+commit)
	return nil
}

// reserveDirName creates an empty folder named name (or "name (1)"...)
// so two jobs can't pick the same name. It is replaced by the clone.
func reserveDirName(dir, name string) (string, error) {
	for i := 0; i < 10000; i++ {
		cand := name
		if i > 0 {
			cand = name + " (" + strconv.Itoa(i) + ")"
		}
		full := filepath.Join(dir, cand)
		if err := os.Mkdir(full, 0o755); err == nil {
			return full, nil
		} else if !os.IsExist(err) {
			return "", err
		}
	}
	return "", fmt.Errorf("no free folder name for %s", name)
}
