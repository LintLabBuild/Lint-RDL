// Package command is the shared command set (spec §4). Every adapter
// (CLI, web, Telegram, MCP...) turns its input into a Command and shows the
// Result; it never touches the disk or network itself. Identity, role and
// rate limits are checked here, in one place.
//
// Config-changing commands (roots, allow-private, setup...) are not part of
// this set on purpose: they exist only in the CLI at the PC.
package command

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/lintlabbuild/lint-rdl/internal/engine"
	"github.com/lintlabbuild/lint-rdl/internal/policy"
	"github.com/lintlabbuild/lint-rdl/internal/state"
)

// Role is what an identity may do.
type Role string

// Roles (spec §8).
const (
	RoleOwner Role = "owner"
	RoleUser  Role = "user"
	RoleAgent Role = "agent"
)

// Identity is who is asking and through which interface.
type Identity struct {
	ID   string `json:"id"`  // e.g. "telegram:123456", "cli:alice", "mcp:claude"
	Via  string `json:"via"` // cli | web | telegram | mcp | ...
	Role Role   `json:"role"`
}

// Command is one request from any interface.
type Command struct {
	Name     string            `json:"name"`
	Args     []string          `json:"args,omitempty"`
	Flags    map[string]string `json:"flags,omitempty"`
	Identity Identity          `json:"identity"`
}

// Flag returns a flag value or "".
func (c Command) Flag(k string) string { return c.Flags[k] }

// Result is what an adapter displays.
type Result struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func fail(err error) Result { return Result{OK: false, Message: err.Error()} }

// ErrDenied means the role may not run this command.
var ErrDenied = errors.New("not allowed for your role")

// Names of the shared commands.
var Names = []string{
	"probe", "add", "add-batch", "hf", "list", "status", "wait", "pause", "resume",
	"cancel", "retry", "relink", "verify", "folders", "ls", "mkdir", "when-done", "power",
	"cancel-power", "limit", "disk", "whoami",
}

// powerCommands need owner (or agent_can_power).
var powerCommands = map[string]bool{"when-done": true, "power": true, "cancel-power": true}

// Limits are per-identity limits.
type Limits struct {
	CommandsPerMinute int   // 0 = 60
	MaxJobSize        int64 // 0 = unlimited; checked when size is known
	AgentCanPower     bool
}

// Dispatcher executes commands against the engine.
type Dispatcher struct {
	M         *engine.Manager
	Paths     *policy.PathPolicy
	URLs      *policy.URLPolicy
	Disk      *policy.DiskGuard
	Audit     *state.Audit
	ShowFiles bool
	Limits    Limits

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func (d *Dispatcher) allowRate(id string) bool {
	per := d.Limits.CommandsPerMinute
	if per <= 0 {
		per = 60
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.buckets == nil {
		d.buckets = map[string]*bucket{}
	}
	b, ok := d.buckets[id]
	now := time.Now()
	if !ok {
		b = &bucket{tokens: float64(per), last: now}
		d.buckets[id] = b
	}
	b.tokens += now.Sub(b.last).Minutes() * float64(per)
	if b.tokens > float64(per) {
		b.tokens = float64(per)
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Allowed reports whether role may run name.
func (d *Dispatcher) Allowed(role Role, name string) bool {
	switch role {
	case RoleOwner:
		return true
	case RoleUser:
		return !powerCommands[name] && name != "limit"
	case RoleAgent:
		if powerCommands[name] {
			return d.Limits.AgentCanPower
		}
		return name != "limit"
	}
	return false
}

// ownsJob: owners control every job; others only their own.
func ownsJob(id Identity, j engine.JobView) bool {
	return id.Role == RoleOwner || j.Owner == id.ID
}

// Dispatch runs one command.
func (d *Dispatcher) Dispatch(ctx context.Context, c Command) Result {
	name := strings.ToLower(strings.TrimSpace(c.Name))
	if c.Identity.ID == "" || c.Identity.Role == "" {
		return fail(errors.New("unknown identity"))
	}
	if !d.allowRate(c.Identity.ID) {
		return fail(errors.New("too many commands; slow down"))
	}
	if !d.Allowed(c.Identity.Role, name) {
		d.log(c, "", "denied")
		return fail(fmt.Errorf("%s: %w (%s)", name, ErrDenied, c.Identity.Role))
	}
	res := d.run(ctx, name, c)
	result := "ok"
	if !res.OK {
		result = "error: " + res.Message
	}
	switch name {
	case "list", "status", "wait", "whoami", "folders", "ls", "disk":
	default:
		url := ""
		if len(c.Args) > 0 && (name == "probe" || name == "add") {
			url = c.Args[0]
		}
		d.log(c, url, result)
	}
	return res
}

func (d *Dispatcher) log(c Command, url, result string) {
	if d.Audit == nil {
		return
	}
	d.Audit.Log(state.AuditEntry{Identity: c.Identity.ID, Via: c.Identity.Via, Command: c.Name, URL: url, Result: result})
}

func needArgs(c Command, n int, usage string) error {
	if len(c.Args) < n {
		return fmt.Errorf("usage: %s", usage)
	}
	return nil
}

func (d *Dispatcher) job(c Command, usage string) (engine.JobView, error) {
	if err := needArgs(c, 1, usage); err != nil {
		return engine.JobView{}, err
	}
	j, err := d.M.Get(c.Args[0])
	if err != nil {
		return j, err
	}
	if !ownsJob(c.Identity, j) {
		return j, fmt.Errorf("job %s belongs to someone else", j.ID)
	}
	return j, nil
}

func (d *Dispatcher) run(ctx context.Context, name string, c Command) Result {
	switch name {
	case "whoami":
		return Result{OK: true, Message: fmt.Sprintf("%s via %s, role %s", c.Identity.ID, c.Identity.Via, c.Identity.Role), Data: c.Identity}

	case "probe":
		if err := needArgs(c, 1, "probe <url>"); err != nil {
			return fail(err)
		}
		r, err := d.M.Probe(ctx, c.Args[0])
		if err != nil {
			return fail(err)
		}
		return Result{OK: true, Message: r.Verdict, Data: r}

	case "add":
		if err := needArgs(c, 1, "add <url> [--to folder] [--name file] [--sha256 hash]"); err != nil {
			return fail(err)
		}
		job, err := d.M.Add(engine.AddRequest{
			URL: c.Args[0], Dir: c.Flag("to"), Name: c.Flag("name"), SHA256: c.Flag("sha256"),
			AllowDuplicate: c.Flag("dup") == "copy", Owner: c.Identity.ID, Via: c.Identity.Via,
			ResumeMode: c.Flag("resume-mode"),
		})
		if err != nil {
			return fail(err)
		}
		return Result{OK: true, Message: fmt.Sprintf("queued %s as %s in %s", job.ID, job.Name, job.Dir), Data: job}

	case "list":
		var out []engine.JobView
		for _, j := range d.M.List() {
			if ownsJob(c.Identity, j) {
				out = append(out, j)
			}
		}
		return Result{OK: true, Message: fmt.Sprintf("%d jobs", len(out)), Data: out}

	case "status":
		j, err := d.job(c, "status <id>")
		if err != nil {
			return fail(err)
		}
		return Result{OK: true, Message: string(j.State), Data: j}

	case "wait":
		timeout := 30 * time.Minute
		if t := c.Flag("timeout"); t != "" {
			dur, err := time.ParseDuration(t)
			if err != nil {
				return fail(fmt.Errorf("bad --timeout: %v", err))
			}
			timeout = dur
		}
		ids := c.Args
		if len(ids) == 0 {
			for _, j := range d.M.List() {
				if ownsJob(c.Identity, j) {
					ids = append(ids, j.ID)
				}
			}
		}
		for _, id := range ids {
			j, err := d.M.Get(id)
			if err != nil {
				return fail(err)
			}
			if !ownsJob(c.Identity, j) {
				return fail(fmt.Errorf("job %s belongs to someone else", id))
			}
		}
		wctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		views, err := d.M.Wait(wctx, ids...)
		sum := Summarize(views)
		if err != nil {
			return Result{OK: false, Message: "timeout; " + sum, Data: views}
		}
		return Result{OK: true, Message: sum, Data: views}

	case "pause", "resume", "cancel", "retry":
		j, err := d.job(c, name+" <id>")
		if err != nil {
			return fail(err)
		}
		switch name {
		case "pause":
			err = d.M.Pause(j.ID)
		case "resume":
			err = d.M.Resume(j.ID)
		case "cancel":
			err = d.M.Cancel(j.ID)
		case "retry":
			if m := c.Flag("resume-mode"); m != "" {
				if err = d.M.SetResumeMode(j.ID, m); err != nil {
					break
				}
			}
			err = d.M.Retry(j.ID)
		}
		if err != nil {
			return fail(err)
		}
		return Result{OK: true, Message: name + " " + j.ID}

	case "relink":
		j, err := d.job(c, "relink <id> <new-url>")
		if err != nil {
			return fail(err)
		}
		if len(c.Args) < 2 {
			return fail(errors.New("usage: relink <id> <new-url>"))
		}
		if m := c.Flag("resume-mode"); m != "" {
			if err := d.M.SetResumeMode(j.ID, m); err != nil {
				return fail(err)
			}
		}
		if err := d.M.Relink(j.ID, c.Args[1], c.Flag("sha256")); err != nil {
			return fail(err)
		}
		return Result{OK: true, Message: "relinked " + j.ID + "; the part already saved is kept"}

	case "verify":
		j, err := d.job(c, "verify <id>")
		if err != nil {
			return fail(err)
		}
		sum, ok, err := d.M.Verify(ctx, j.ID)
		if err != nil {
			return fail(err)
		}
		msg := "SHA-256 OK " + sum
		if !ok {
			msg = "SHA-256 MISMATCH " + sum
		}
		return Result{OK: ok, Message: msg, Data: map[string]any{"sha256": sum, "match": ok}}

	case "folders":
		sf := d.Paths.SaveFolders()
		var lines []string
		for i, f := range sf {
			src := ""
			if f.Source != "root" {
				src = " (pinned in " + f.Source + ")"
			}
			lines = append(lines, fmt.Sprintf("%d) %s  %s%s", i+1, f.Label, f.Path, src))
		}
		return Result{OK: true, Message: strings.Join(lines, "\n"), Data: sf}

	case "ls":
		dir := ""
		if len(c.Args) > 0 {
			dir = c.Args[0]
		}
		ents, err := d.Paths.List(dir, d.ShowFiles)
		if err != nil {
			return fail(err)
		}
		return Result{OK: true, Message: fmt.Sprintf("%d entries", len(ents)), Data: ents}

	case "mkdir":
		if err := needArgs(c, 1, "mkdir <name> [--in folder]"); err != nil {
			return fail(err)
		}
		p, err := d.Paths.Mkdir(c.Flag("in"), c.Args[0])
		if err != nil {
			return fail(err)
		}
		return Result{OK: true, Message: "created " + p, Data: p}

	case "disk":
		type row struct {
			Folder string `json:"folder"`
			policy.DiskInfo
		}
		var rows []row
		var lines []string
		for _, r := range d.Paths.Roots {
			info, err := policy.StatDisk(r)
			if err != nil {
				continue
			}
			rows = append(rows, row{r, info})
			lines = append(lines, fmt.Sprintf("%s: %s free of %s", r, policy.HumanBytes(int64(info.Free)), policy.HumanBytes(int64(info.Total))))
		}
		return Result{OK: true, Message: strings.Join(lines, "\n"), Data: rows}

	case "limit":
		return fail(errors.New("change speed_limit with `rdl config set speed_limit <value>` at the PC (live limit arrives with the daemon)"))

	case "hf", "add-batch":
		return fail(fmt.Errorf("%s: use the CLI for now (adapters get it with the daemon)", name))

	case "when-done", "power", "cancel-power":
		return fail(errors.New("power actions arrive with the daemon (phase 2)"))
	}
	return fail(fmt.Errorf("unknown command %q", name))
}

// Summarize gives a one-line, token-cheap summary of jobs (for wait).
func Summarize(views []engine.JobView) string {
	counts := map[state.JobState]int{}
	var failed []string
	for _, v := range views {
		counts[v.State]++
		if v.State == state.StateFailed {
			failed = append(failed, v.ID+": "+v.Error)
		}
	}
	var parts []string
	for _, s := range []state.JobState{state.StateDone, state.StateFailed, state.StateCancelled, state.StatePaused,
		state.StateRunning, state.StateRetrying, state.StateQueued, state.StatePausedDisk, state.StatePausedNoDir, state.StateVerifying} {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	s := strings.Join(parts, ", ")
	if s == "" {
		s = "no jobs"
	}
	if len(failed) > 0 {
		s += " | " + strings.Join(failed, "; ")
	}
	return s
}
