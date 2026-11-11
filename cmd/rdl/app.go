package main

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/lintlabbuild/lint-rdl/internal/command"
	"github.com/lintlabbuild/lint-rdl/internal/config"
	"github.com/lintlabbuild/lint-rdl/internal/engine"
	"github.com/lintlabbuild/lint-rdl/internal/gitdl"
	"github.com/lintlabbuild/lint-rdl/internal/hf"
	"github.com/lintlabbuild/lint-rdl/internal/policy"
	"github.com/lintlabbuild/lint-rdl/internal/state"
)

// app bundles everything a CLI command needs.
type app struct {
	cfg     *config.Config
	paths   *policy.PathPolicy
	urls    *policy.URLPolicy
	disk    *policy.DiskGuard
	journal *state.Journal
	audit   *state.Audit
	m       *engine.Manager
	lock    *state.Lock
	disp    *command.Dispatcher
	me      command.Identity
	onEvent func(engine.Event)
}

func loadConfig() (*config.Config, error) {
	path := os.Getenv("RDL_CONFIG")
	if path == "" {
		path = config.DefaultPath()
	}
	return config.Load(path)
}

// openApp loads config, journal and the engine. If needLock is true the
// single-instance lock is taken (commands that run downloads or change
// jobs); otherwise the journal is only read and written for new jobs.
func openApp(needLock bool) (*app, error) {
	cfg, err := loadConfig()
	if err != nil {
		return nil, err
	}
	a := &app{cfg: cfg}
	a.paths = cfg.PathPolicy()
	if a.urls, err = cfg.URLPolicy(); err != nil {
		return nil, err
	}
	a.disk = &policy.DiskGuard{MinFree: uint64(cfg.DiskMinFreeGB * (1 << 30))}
	sd := config.StateDir()
	if needLock {
		if a.lock, err = state.AcquireLock(sd); err != nil {
			return nil, fmt.Errorf("%w\nStop the other rdl (Ctrl+C in its window) first; live control of a running rdl arrives with the daemon", err)
		}
	}
	if a.journal, err = state.OpenJournal(filepath.Join(sd, "jobs")); err != nil {
		return nil, err
	}
	if a.audit, err = state.OpenAudit(filepath.Join(sd, "audit.log"), 0); err != nil {
		return nil, err
	}
	speed, _ := cfg.SpeedLimitBytes()
	opts := engine.Options{
		URLPolicy: a.urls, Paths: a.paths, Disk: a.disk, Journal: a.journal, Audit: a.audit,
		MaxParallel:     cfg.MaxParallelJobs,
		ChunkSize:       int64(cfg.ChunkMB) << 20,
		StallTimeout:    cfg.StallTimeout(),
		LowSpeedBytes:   cfg.LowSpeedBytes,
		LowSpeedWindow:  time.Duration(cfg.LowSpeedSeconds) * time.Second,
		SpeedLimit:      speed,
		RetryAfterCap:   time.Duration(cfg.RetryAfterCapSec) * time.Second,
		BlockExtensions: cfg.BlockExtensions,
		GitPath:         gitdl.LookPath(),
		GitHosts:        cfg.GitHosts,
		GitFullHistory:  cfg.GitFullHistory,
		ResumeMode:      cfg.ResumeMode,
		OnEvent: func(ev engine.Event) {
			if a.onEvent != nil {
				a.onEvent(ev)
			}
		},
	}
	if tok := os.Getenv("RDL_HF_TOKEN"); tok != "" {
		opts.Authorize = func(req *http.Request) {
			if hf.IsHFHost(req.URL) {
				req.Header.Set("Authorization", "Bearer "+tok)
			}
		}
	}
	if a.m, err = engine.New(opts); err != nil {
		return nil, err
	}
	name := "owner"
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	a.me = command.Identity{ID: "cli:" + name, Via: "cli", Role: command.RoleOwner}
	a.disp = &command.Dispatcher{M: a.m, Paths: a.paths, URLs: a.urls, Disk: a.disk, Audit: a.audit, ShowFiles: true}
	return a, nil
}

func (a *app) close() {
	if a.m != nil {
		a.m.Close()
	}
	a.lock.Release()
}

var errNoRoots = errors.New("no save folders configured; run `rdl setup` or `rdl roots add <folder>`")
