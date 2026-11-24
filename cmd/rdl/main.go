// Command rdl is a resumable download manager: downloads that survive
// network drops and shutdowns, and never run, open or send out what they
// download.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/lintlabbuild/lint-rdl/internal/command"
	"github.com/lintlabbuild/lint-rdl/internal/config"
	"github.com/lintlabbuild/lint-rdl/internal/engine"
	"github.com/lintlabbuild/lint-rdl/internal/hf"
	"github.com/lintlabbuild/lint-rdl/internal/policy"
	"github.com/lintlabbuild/lint-rdl/internal/state"
)

var version = "0.1.0-dev"

const usage = `rdl - resumable download manager

Downloads:
  rdl probe <url>                       report size, resumability, checksum, name (no download)
  rdl get <url>... [flags]              show what it is, then download in this window (resumes if run again)
  rdl add <url> [flags]                 queue a download (run it with "rdl run")
  rdl add-batch <manifest.json>         queue many: [{"url","to","name","sha256"}]
  rdl hf <owner/repo> <path>... [--rev r] [--to dir]
                                        Hugging Face: look up size + SHA-256, then queue
  rdl run [--exit-when-done]            process the queue in this window
  rdl list | status <id> | wait [<id>...] [--timeout 30m]
  rdl pause|resume|cancel|remove|verify <id>
  rdl retry <id> [--resume-mode ratchet|missing-only|restart]
  rdl relink <id> <new-url> [--sha256 h] [--resume-mode m]
                                        continue a job from a new link (expired temporary links)

Folders:
  rdl folders | ls [path] | mkdir <name> [--in folder] | disk

At the PC only (config):
  rdl setup                             first-time setup
  rdl config [show|path|set <key> <value>]
  rdl roots [list|add|remove] <folder>
  rdl deny [list|add|remove] <folder>
  rdl allow-private [list|add|remove] <ip or cidr>
  rdl audit [-n 50]
  rdl whoami | version

Flags for get/add: --to <folder|@favorite>  --name <file>  --sha256 <hash>  --dup copy
                   --all (web folders: every file)  -y (don't ask)  --json
                   --resume-mode auto|ratchet|missing-only|restart (server can't resume)

rdl get shows what a link is (type, size, files inside) and, in a terminal,
asks where to save it (configured folders and folders pinned in File Explorer /
your file manager). Git repository links are cloned if Git is installed.
Streaming sites (YouTube, Netflix, Spotify...) and stream playlists are refused.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stdout, usage)
		return 0
	}
	cmd, rest := args[0], args[1:]
	var err error
	switch cmd {
	case "version", "--version":
		fmt.Fprintln(stdout, "rdl", version)
	case "setup":
		err = cmdSetup(rest, stdout)
	case "config":
		err = cmdConfig(rest, stdout)
	case "roots":
		err = cmdList(rest, stdout, "roots")
	case "deny":
		err = cmdList(rest, stdout, "deny")
	case "allow-private":
		err = cmdList(rest, stdout, "allow-private")
	case "probe":
		err = cmdProbe(rest, stdout)
	case "get":
		err = cmdGet(rest, stdout, stderr)
	case "add":
		err = cmdAdd(rest, stdout)
	case "add-batch":
		err = cmdAddBatch(rest, stdout)
	case "hf":
		err = cmdHF(rest, stdout)
	case "run":
		err = cmdRun(rest, stdout, stderr)
	case "list", "ls-jobs":
		err = cmdJobs(rest, stdout)
	case "status", "pause", "resume", "cancel", "retry", "relink", "verify", "whoami", "folders", "ls", "mkdir", "disk":
		err = cmdDispatch(cmd, rest, stdout)
	case "remove":
		err = cmdRemove(rest, stdout)
	case "wait":
		err = cmdWait(rest, stdout)
	case "audit":
		err = cmdAudit(rest, stdout)
	case "limit":
		err = cmdLimit(rest, stdout)
	case "when-done", "power", "cancel-power", "pair", "unpair", "daemon", "mcp":
		err = fmt.Errorf("%s arrives in a later phase (see docs/USAGE.md)", cmd)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
		return 2
	}
	if err != nil {
		var ee exitError
		if errors.As(err, &ee) {
			if ee.msg != "" {
				fmt.Fprintln(stderr, ee.msg)
			}
			return ee.code
		}
		fmt.Fprintln(stderr, "rdl:", err)
		return 1
	}
	return 0
}

type exitError struct {
	code int
	msg  string
}

func (e exitError) Error() string { return e.msg }

// parseInterspersed lets flags appear before or after positional args.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func newFlags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ---- config commands (PC only) ----

func cmdSetup(args []string, w io.Writer) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if len(cfg.Roots) == 0 {
		var root string
		if len(args) > 0 {
			root = args[0]
		} else if h, err := os.UserHomeDir(); err == nil {
			root = filepath.Join(h, "Downloads")
		}
		if root != "" {
			abs, _ := filepath.Abs(root)
			if err := os.MkdirAll(abs, 0o755); err != nil {
				return err
			}
			cfg.Roots = []string{abs}
		}
	}
	if err := cfg.Save(); err != nil {
		return err
	}
	fmt.Fprintf(w, "Config:  %s\nState:   %s\nSave folders:\n", cfg.Path(), config.StateDir())
	for _, r := range cfg.Roots {
		fmt.Fprintln(w, "  "+r)
	}
	fmt.Fprintln(w, "\nAdd more with `rdl roots add <folder>`. Try `rdl probe <url>` and `rdl get <url>`.")
	return nil
}

func cmdConfig(args []string, w io.Writer) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	sub := "show"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "show":
		fmt.Fprint(w, cfg.Render())
	case "path":
		fmt.Fprintln(w, cfg.Path())
	case "set":
		if len(args) != 3 {
			return errors.New("usage: rdl config set <key> <value>")
		}
		key, val := args[1], args[2]
		if strings.HasPrefix(key, "roots") || strings.HasPrefix(key, "allow_private") || strings.HasPrefix(key, "deny") || strings.HasPrefix(key, "domain_allowlist") {
			return errors.New("use `rdl roots|deny|allow-private` for lists, or edit the file")
		}
		src := cfg.Render()
		// Replace "key: ..." or "  sub: ..." for section.key.
		lines := strings.Split(src, "\n")
		found := false
		if i := strings.IndexByte(key, '.'); i > 0 {
			sec, sub := key[:i], key[i+1:]
			in := false
			for n, l := range lines {
				if strings.HasPrefix(l, sec+":") {
					in = true
					continue
				}
				if in && strings.HasPrefix(l, "  "+sub+":") {
					lines[n] = "  " + sub + ": " + val
					found = true
					break
				}
				if in && !strings.HasPrefix(l, "  ") {
					break
				}
			}
		} else {
			for n, l := range lines {
				if strings.HasPrefix(l, key+":") {
					lines[n] = key + ": " + val
					found = true
					break
				}
			}
		}
		if !found {
			return fmt.Errorf("unknown key %q", key)
		}
		ncfg, err := config.Parse(strings.Join(lines, "\n"), cfg.Path())
		if err != nil {
			return err
		}
		if err := ncfg.Save(); err != nil {
			return err
		}
		fmt.Fprintf(w, "%s = %s\n", key, val)
	default:
		return fmt.Errorf("unknown config command %q", sub)
	}
	return nil
}

func cmdList(args []string, w io.Writer, which string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	var list *[]string
	switch which {
	case "roots":
		list = &cfg.Roots
	case "deny":
		list = &cfg.Deny
	case "allow-private":
		list = &cfg.AllowPrivate
	}
	sub := "list"
	if len(args) > 0 {
		sub = args[0]
	}
	switch sub {
	case "list":
		for _, r := range *list {
			fmt.Fprintln(w, r)
		}
		return nil
	case "add", "remove":
		if len(args) != 2 {
			return fmt.Errorf("usage: rdl %s %s <value>", which, sub)
		}
	default:
		return fmt.Errorf("usage: rdl %s [list|add|remove] <value>", which)
	}
	val := args[1]
	if which != "allow-private" {
		abs, err := filepath.Abs(val)
		if err != nil {
			return err
		}
		val = abs
		if which == "roots" && sub == "add" {
			if st, err := os.Stat(val); err != nil || !st.IsDir() {
				return fmt.Errorf("%s is not an existing folder", val)
			}
			for _, f := range cfg.PathPolicy().Forbidden {
				if policy.IsWithin(f, val) || policy.IsWithin(val, f) {
					return fmt.Errorf("%s overlaps the protected folder %s", val, f)
				}
			}
		}
	} else if sub == "add" {
		p, err := policy.ParseAllowPrivate(val)
		if err != nil {
			return err
		}
		val = p.String()
		if p.Addr().Is4() && p.Bits() == 32 || p.Addr().Is6() && p.Bits() == 128 {
			val = p.Addr().String()
		}
	}
	idx := -1
	for i, r := range *list {
		if strings.EqualFold(r, val) {
			idx = i
		}
	}
	if sub == "add" {
		if idx >= 0 {
			fmt.Fprintln(w, "already listed:", val)
			return nil
		}
		*list = append(*list, val)
	} else {
		if idx < 0 {
			return fmt.Errorf("%s is not listed", val)
		}
		*list = append((*list)[:idx], (*list)[idx+1:]...)
	}
	if err := cfg.Save(); err != nil {
		return err
	}
	fmt.Fprintf(w, "%s %s: %s\n", which, map[string]string{"add": "added", "remove": "removed"}[sub], val)
	if which == "allow-private" && sub == "add" {
		fmt.Fprintln(w, "Warning: rdl may now download from this private address. Remove it with `rdl allow-private remove`.")
	}
	return nil
}

// ---- downloads ----

func cmdProbe(args []string, w io.Writer) error {
	fs := newFlags("probe")
	asJSON := fs.Bool("json", false, "")
	pos, err := parseInterspersed(fs, args)
	if err != nil || len(pos) != 1 {
		return errors.New("usage: rdl probe <url> [--json]")
	}
	a, err := openApp(false)
	if err != nil {
		return err
	}
	defer a.close()
	ctx, cancel := signalContext()
	defer cancel()
	r, err := a.m.Probe(ctx, pos[0])
	if err != nil {
		return err
	}
	if *asJSON {
		return printJSON(w, r)
	}
	printProbe(w, r, 30)
	return nil
}

type addFlags struct {
	to, name, sha, dup, rmode *string
	asJSON, all, yes          *bool
}

func newAddFlags(name string) (*flag.FlagSet, addFlags) {
	fs := newFlags(name)
	return fs, addFlags{
		to:     fs.String("to", "", ""),
		name:   fs.String("name", "", ""),
		sha:    fs.String("sha256", "", ""),
		dup:    fs.String("dup", "", ""),
		rmode:  fs.String("resume-mode", "", ""),
		asJSON: fs.Bool("json", false, ""),
		all:    fs.Bool("all", false, ""),
		yes:    fs.Bool("y", false, ""),
	}
}

func cmdAdd(args []string, w io.Writer) error {
	fs, f := newAddFlags("add")
	pos, err := parseInterspersed(fs, args)
	if err != nil || len(pos) == 0 {
		return errors.New("usage: rdl add <url>... [--to folder] [--name file] [--sha256 hash] [--dup copy]")
	}
	if len(pos) > 1 && *f.name != "" {
		return errors.New("--name works with one URL only")
	}
	a, err := openApp(false)
	if err != nil {
		return err
	}
	defer a.close()
	if len(a.paths.Roots) == 0 {
		return errNoRoots
	}
	if *f.all {
		ctx, cancel := signalContext()
		plan, err := planDownloads(ctx, a, pos, true, true, w)
		cancel()
		if err != nil {
			return err
		}
		pos = pos[:0]
		for _, p := range plan {
			pos = append(pos, p.url)
		}
	}
	var jobs []*state.Job
	for _, u := range pos {
		job, err := a.m.Add(engine.AddRequest{URL: u, Dir: *f.to, Name: *f.name, SHA256: *f.sha,
			AllowDuplicate: *f.dup == "copy", Owner: a.me.ID, Via: "cli", ResumeMode: *f.rmode})
		if err != nil {
			return fmt.Errorf("%s: %w", u, err)
		}
		jobs = append(jobs, job)
		if !*f.asJSON {
			fmt.Fprintf(w, "queued %s  %s -> %s\n", job.ID, job.Name, job.Dir)
		}
	}
	if *f.asJSON {
		return printJSON(w, jobs)
	}
	fmt.Fprintln(w, "Run `rdl run` to start (or it is picked up by a running `rdl run`).")
	return nil
}

// manifestEntry is one line of an add-batch manifest.
type manifestEntry struct {
	URL    string `json:"url"`
	To     string `json:"to"`
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

func cmdAddBatch(args []string, w io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: rdl add-batch <manifest.json>")
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	var entries []manifestEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("manifest must be a JSON list of {url,to,name,sha256}: %w", err)
	}
	a, err := openApp(false)
	if err != nil {
		return err
	}
	defer a.close()
	for i, e := range entries {
		job, err := a.m.Add(engine.AddRequest{URL: e.URL, Dir: e.To, Name: e.Name, SHA256: e.SHA256, ExpectedSize: e.Size, Owner: a.me.ID, Via: "cli"})
		if err != nil {
			fmt.Fprintf(w, "#%d %s: %v\n", i+1, e.URL, err)
			continue
		}
		fmt.Fprintf(w, "queued %s  %s -> %s\n", job.ID, job.Name, job.Dir)
	}
	return nil
}

func cmdHF(args []string, w io.Writer) error {
	fs := newFlags("hf")
	rev := fs.String("rev", "main", "")
	to := fs.String("to", "", "")
	now := fs.Bool("get", false, "")
	pos, err := parseInterspersed(fs, args)
	if err != nil || len(pos) < 2 {
		return errors.New("usage: rdl hf <owner/repo> <path>... [--rev main|<commit>] [--to folder] [--get]")
	}
	a, err := openApp(*now)
	if err != nil {
		return err
	}
	defer a.close()
	ctx, cancel := signalContext()
	defer cancel()
	files, err := hf.Lookup(ctx, a.m.Client(), pos[0], *rev, pos[1:], os.Getenv("RDL_HF_TOKEN"))
	if err != nil {
		return err
	}
	if *rev == "main" {
		fmt.Fprintln(w, "Tip: pin a commit with --rev <sha> so files can't change mid-download.")
	}
	var ids []string
	for _, f := range files {
		job, err := a.m.Add(engine.AddRequest{URL: f.URL, Dir: *to, SHA256: f.SHA256, ExpectedSize: f.Size, Owner: a.me.ID, Via: "cli"})
		if err != nil {
			fmt.Fprintf(w, "%s: %v\n", f.Path, err)
			continue
		}
		ids = append(ids, job.ID)
		sum := "no SHA-256 (not an LFS file)"
		if f.SHA256 != "" {
			sum = "SHA-256 " + f.SHA256[:12] + "..."
		}
		fmt.Fprintf(w, "queued %s  %s  %s  %s\n", job.ID, job.Name, policy.HumanBytes(f.Size), sum)
	}
	if *now {
		return runJobs(a, ids, w, os.Stderr)
	}
	return nil
}

func cmdGet(args []string, w, ew io.Writer) error {
	fs, f := newAddFlags("get")
	pos, err := parseInterspersed(fs, args)
	if err != nil || len(pos) == 0 {
		return errors.New("usage: rdl get <url>... [--to folder] [--name file] [--sha256 hash]")
	}
	if len(pos) > 1 && *f.name != "" {
		return errors.New("--name works with one URL only")
	}
	a, err := openApp(true)
	if err != nil {
		return err
	}
	defer a.close()
	if len(a.paths.Roots) == 0 {
		return errNoRoots
	}
	// Tell the user what each link is before downloading anything.
	interactive := isInteractive() && !*f.yes && !*f.asJSON
	pctx, pcancel := signalContext()
	plan, err := planDownloads(pctx, a, pos, *f.all, *f.asJSON, w)
	pcancel()
	if err != nil {
		return err
	}
	dir := *f.to
	if interactive {
		if dir == "" {
			if dir, err = pickFolder(a, w); err != nil {
				return err
			}
		}
		what := fmt.Sprintf("%d downloads", len(plan))
		if len(plan) == 1 {
			what = "this"
		}
		target := dir
		if target == "" {
			target = a.paths.DefaultRoot()
		}
		if !confirm(w, fmt.Sprintf("Download %s into %s?", what, target)) {
			return exitError{code: 1, msg: "cancelled"}
		}
	}
	var ids []string
	for _, p := range plan {
		u := p.url
		sha := *f.sha
		if sha == "" {
			sha = p.sha
		}
		job, err := a.m.Add(engine.AddRequest{URL: u, Dir: dir, Name: *f.name, SHA256: sha, ExpectedSize: p.size,
			AllowDuplicate: *f.dup == "copy", Owner: a.me.ID, Via: "cli", ResumeMode: *f.rmode})
		if errors.Is(err, engine.ErrDuplicate) {
			// Same URL already known: resume that job instead.
			if nu, perr := a.urls.CheckRawURL(u); perr == nil {
				if v, ok := a.m.FindByURL(nu.String()); ok {
					switch v.State {
					case state.StateDone:
						fmt.Fprintf(w, "%s already downloaded: %s (use --dup copy for another copy)\n", v.ID, v.FinalPath)
						continue
					case state.StatePaused:
						a.m.Resume(v.ID)
					}
					fmt.Fprintf(w, "resuming %s  %s (%s already on disk)\n", v.ID, v.Name, policy.HumanBytes(v.Downloaded))
					ids = append(ids, v.ID)
					continue
				}
			}
		}
		if err != nil {
			return fmt.Errorf("%s: %w", u, err)
		}
		ids = append(ids, job.ID)
	}
	if len(ids) == 0 {
		return nil
	}
	if *f.asJSON {
		return runJobsJSON(a, ids, w)
	}
	return runJobs(a, ids, w, ew)
}

func cmdRun(args []string, w, ew io.Writer) error {
	fs := newFlags("run")
	exit := fs.Bool("exit-when-done", false, "")
	if _, err := parseInterspersed(fs, args); err != nil {
		return errors.New("usage: rdl run [--exit-when-done]")
	}
	a, err := openApp(true)
	if err != nil {
		return err
	}
	defer a.close()
	ctx, cancel := signalContext()
	defer cancel()
	p := newProgress(w)
	a.onEvent = p.event
	a.m.Start()
	fmt.Fprintln(w, "rdl is running the queue. Ctrl+C stops; everything resumes next time.")
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	rescan := time.NewTicker(3 * time.Second)
	defer rescan.Stop()
	for {
		select {
		case <-ctx.Done():
			p.finish()
			fmt.Fprintln(w, "\nStopped. Partial downloads are kept; run `rdl run` to continue.")
			return nil
		case <-rescan.C:
			a.m.Rescan()
		case <-tick.C:
			views := a.m.List()
			p.draw(views)
			if *exit && allSettled(views) {
				p.finish()
				return summaryExit(views, w)
			}
		}
	}
}

func allSettled(vs []engine.JobView) bool {
	for _, v := range vs {
		if !v.State.Terminal() && v.State != state.StatePaused {
			return false
		}
	}
	return true
}

func runJobs(a *app, ids []string, w, ew io.Writer) error {
	ctx, cancel := signalContext()
	defer cancel()
	p := newProgress(w)
	a.onEvent = p.event
	a.m.Start()
	done := make(chan struct{})
	var views []engine.JobView
	var werr error
	go func() {
		views, werr = a.m.Wait(ctx, ids...)
		close(done)
	}()
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-done:
			p.finish()
			if werr != nil {
				fmt.Fprintln(w, "\nStopped. Run the same command again to resume.")
				return exitError{code: 130}
			}
			return summaryExit(views, w)
		case <-tick.C:
			var vs []engine.JobView
			for _, id := range ids {
				if v, err := a.m.Get(id); err == nil {
					vs = append(vs, v)
				}
			}
			p.draw(vs)
		}
	}
}

func runJobsJSON(a *app, ids []string, w io.Writer) error {
	ctx, cancel := signalContext()
	defer cancel()
	a.m.Start()
	views, err := a.m.Wait(ctx, ids...)
	printJSON(w, views)
	if err != nil {
		return exitError{code: 130}
	}
	for _, v := range views {
		if v.State != state.StateDone {
			return exitError{code: 1}
		}
	}
	return nil
}

func summaryExit(views []engine.JobView, w io.Writer) error {
	failed := 0
	for _, v := range views {
		switch v.State {
		case state.StateDone:
			if v.Kind == "git" {
				fmt.Fprintf(w, "done    %s  %s  Git repository, %d files, commit %.12s\n", v.ID, v.FinalPath, v.FileCount, v.Commit)
				continue
			}
			check := "SHA-256 " + v.SHA256
			if v.Verified {
				check = "SHA-256 OK (matches expected)"
			}
			fmt.Fprintf(w, "done    %s  %s  %s  %s\n", v.ID, v.FinalPath, policy.HumanBytes(v.ExpectedSize), check)
		case state.StateFailed:
			failed++
			fmt.Fprintf(w, "FAILED  %s  %s  %s\n", v.ID, v.Name, v.Error)
		default:
			fmt.Fprintf(w, "%-7s %s  %s\n", v.State, v.ID, v.Name)
		}
	}
	if failed > 0 {
		return exitError{code: 1}
	}
	return nil
}

func cmdJobs(args []string, w io.Writer) error {
	fs := newFlags("list")
	asJSON := fs.Bool("json", false, "")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	a, err := openApp(false)
	if err != nil {
		return err
	}
	defer a.close()
	views := a.m.List()
	if *asJSON {
		return printJSON(w, views)
	}
	if len(views) == 0 {
		fmt.Fprintln(w, "no jobs")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTATE\tPROGRESS\tSIZE\tNAME\tFOLDER")
	for _, v := range views {
		prog := policy.HumanBytes(v.Downloaded)
		if p := v.Progress(); p >= 0 {
			prog = fmt.Sprintf("%.1f%%", p*100)
		}
		if v.State == state.StateDone {
			prog = "100%"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", v.ID, v.State, prog, policy.HumanBytes(v.ExpectedSize), v.Name, v.Dir)
	}
	return tw.Flush()
}

func cmdDispatch(name string, args []string, w io.Writer) error {
	fs := newFlags(name)
	asJSON := fs.Bool("json", false, "")
	in := fs.String("in", "", "")
	rmode := fs.String("resume-mode", "", "")
	sha := fs.String("sha256", "", "")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	mutating := name == "pause" || name == "resume" || name == "cancel" || name == "retry" || name == "relink"
	a, err := openApp(mutating)
	if err != nil {
		return err
	}
	defer a.close()
	ctx, cancel := signalContext()
	defer cancel()
	flags := map[string]string{}
	if *in != "" {
		flags["in"] = *in
	}
	if *rmode != "" {
		flags["resume-mode"] = *rmode
	}
	if *sha != "" {
		flags["sha256"] = *sha
	}
	res := a.disp.Dispatch(ctx, command.Command{Name: name, Args: pos, Flags: flags, Identity: a.me})
	if *asJSON {
		printJSON(w, res)
	} else {
		printResult(w, name, res)
	}
	if !res.OK {
		return exitError{code: 1}
	}
	return nil
}

func printResult(w io.Writer, name string, res command.Result) {
	if !res.OK {
		fmt.Fprintln(w, "error:", res.Message)
		return
	}
	switch d := res.Data.(type) {
	case []policy.Entry:
		for _, e := range d {
			if e.IsDir {
				fmt.Fprintf(w, "[dir]  %s\n", e.Name)
			} else {
				fmt.Fprintf(w, "       %s  (%s)\n", e.Name, policy.HumanBytes(e.Size))
			}
		}
		if len(d) == 0 {
			fmt.Fprintln(w, "(empty)")
		}
	case engine.JobView:
		printJSON(w, d)
	default:
		fmt.Fprintln(w, res.Message)
	}
}

func cmdRemove(args []string, w io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: rdl remove <id>... (forgets finished/failed/cancelled jobs; files stay)")
	}
	a, err := openApp(true)
	if err != nil {
		return err
	}
	defer a.close()
	for _, id := range args {
		if err := a.m.Remove(id); err != nil {
			return fmt.Errorf("%s: %w", id, err)
		}
		fmt.Fprintln(w, "removed", id)
	}
	return nil
}

func cmdWait(args []string, w io.Writer) error {
	fs := newFlags("wait")
	timeout := fs.Duration("timeout", 30*time.Minute, "")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return err
	}
	// Waiting needs a runner; in phase 1 that is this process.
	a, err := openApp(true)
	if err != nil {
		return err
	}
	defer a.close()
	ctx, cancel := signalContext()
	defer cancel()
	a.m.Start()
	ctx, cancel2 := context.WithTimeout(ctx, *timeout)
	defer cancel2()
	views, err := a.m.Wait(ctx, pos...)
	fmt.Fprintln(w, command.Summarize(views))
	if err != nil {
		return exitError{code: 1, msg: "timeout"}
	}
	return nil
}

func cmdAudit(args []string, w io.Writer) error {
	fs := newFlags("audit")
	n := fs.Int("n", 50, "")
	if _, err := parseInterspersed(fs, args); err != nil {
		return err
	}
	a, err := state.OpenAudit(filepath.Join(config.StateDir(), "audit.log"), 0)
	if err != nil {
		return err
	}
	entries, err := a.Tail(*n)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tWHO\tVIA\tCOMMAND\tJOB\tRESULT\tURL / DEST")
	for _, e := range entries {
		target := e.URL
		if e.Dest != "" {
			target += " -> " + e.Dest
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", e.Time.Local().Format("2006-01-02 15:04:05"), e.Identity, e.Via, e.Command, e.JobID, e.Result, target)
	}
	return tw.Flush()
}

func cmdLimit(args []string, w io.Writer) error {
	if len(args) != 1 {
		return errors.New("usage: rdl limit <speed|off>   e.g. 5MB/s")
	}
	return cmdConfig([]string{"set", "speed_limit", args[0]}, w)
}

func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// ---- progress display ----

type progress struct {
	mu       sync.Mutex
	w        io.Writer
	notices  []string
	lastLine int
}

func newProgress(w io.Writer) *progress { return &progress{w: w} }

func (p *progress) event(ev engine.Event) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch ev.Type {
	case engine.EvNotice, engine.EvFailed:
		p.notices = append(p.notices, fmt.Sprintf("%s: %s", ev.Job.ID, ev.Message))
	case engine.EvState:
		if ev.Job.State == state.StateRetrying || ev.Job.State == state.StatePausedDisk || ev.Job.State == state.StatePausedNoDir {
			p.notices = append(p.notices, fmt.Sprintf("%s: %s", ev.Job.ID, ev.Message))
		}
	}
}

func (p *progress) draw(views []engine.JobView) {
	p.mu.Lock()
	notices := p.notices
	p.notices = nil
	p.mu.Unlock()
	for _, n := range notices {
		p.clear()
		fmt.Fprintln(p.w, n)
	}
	var parts []string
	sort.SliceStable(views, func(i, j int) bool {
		return views[i].State == state.StateRunning && views[j].State != state.StateRunning
	})
	for _, v := range views {
		if v.State.Terminal() {
			continue
		}
		s := fmt.Sprintf("%s %s", v.ID, truncate(v.Name, 28))
		if pr := v.Progress(); pr >= 0 {
			s += fmt.Sprintf(" %5.1f%%", pr*100)
		} else {
			s += " " + policy.HumanBytes(v.Downloaded)
		}
		switch v.State {
		case state.StateRunning:
			if v.CatchingUp > 0 {
				s += " verifying saved part " + policy.HumanBytes(v.CatchingUp) + "/" + policy.HumanBytes(v.Downloaded)
				break
			}
			s += " " + policy.HumanBytes(int64(v.Speed)) + "/s"
			if v.ETA > 0 {
				s += " ETA " + (time.Duration(v.ETA) * time.Second).Round(time.Second).String()
			}
		default:
			s += " [" + string(v.State) + "]"
		}
		parts = append(parts, s)
	}
	line := strings.Join(parts, " | ")
	if len(line) > 150 {
		line = line[:150]
	}
	p.clear()
	fmt.Fprint(p.w, line)
	p.lastLine = len(line)
}

func (p *progress) clear() {
	if p.lastLine > 0 {
		fmt.Fprint(p.w, "\r"+strings.Repeat(" ", p.lastLine)+"\r")
		p.lastLine = 0
	}
}

func (p *progress) finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.clear()
	for _, n := range p.notices {
		fmt.Fprintln(p.w, n)
	}
	p.notices = nil
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
