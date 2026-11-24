package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lintlabbuild/lint-rdl/internal/command"
	"github.com/lintlabbuild/lint-rdl/internal/engine"
	"github.com/lintlabbuild/lint-rdl/internal/policy"
	"github.com/lintlabbuild/lint-rdl/internal/state"
)

type tool struct {
	Name        string
	Description string
	Schema      map[string]any
	ReadOnly    bool
	run         func(ctx context.Context, s *Server, args json.RawMessage) (any, error)
}

func obj(props map[string]any, required ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func str(desc string) map[string]any { return map[string]any{"type": "string", "description": desc} }

var (
	pURL        = str("Public http(s) link")
	pID         = str("Job id from add/list")
	pTo         = str(`Save folder: a path inside a save folder, a path relative to the default one (e.g. "models/vae"), or "@Label/sub". Omit for the default folder.`)
	pSHA        = str("Expected SHA-256 (64 hex). The file is rejected if it doesn't match.")
	pResumeMode = map[string]any{"type": "string", "enum": engine.ResumeModes,
		"description": "What to do if the server can't resume: auto (=ratchet), ratchet (re-read and verify the saved part), missing-only (stop instead of re-downloading), restart"}
)

var tools []tool

func init() {
	tools = []tool{
		{Name: "probe", ReadOnly: true,
			Description: "Inspect a link without downloading: real file type, size, whether resume works, known SHA-256, file name, and what is inside (ZIP files, model tensors, web-folder files, repository files). Use before add when unsure what a link is.",
			Schema:      obj(map[string]any{"url": pURL}, "url"), run: runProbe},
		{Name: "add",
			Description: "Queue one download (starts right away). A GitHub/GitLab repository link is cloned with Git if installed. For a web folder link set all=true to queue every file in it. Returns the job id.",
			Schema: obj(map[string]any{"url": pURL, "to": pTo, "name": str("File name to save as (optional)"), "sha256": pSHA,
				"resume_mode": pResumeMode, "all": map[string]any{"type": "boolean", "description": "Web folder links: queue every file in the folder (not subfolders)"}}, "url"),
			run: runAdd},
		{Name: "add_batch",
			Description: "Queue many downloads in one call (max 100). Prefer this over many add calls. Each item may set its own folder and SHA-256.",
			Schema: obj(map[string]any{
				"items": map[string]any{"type": "array", "maxItems": 100, "items": obj(map[string]any{
					"url": pURL, "to": pTo, "name": str("File name (optional)"), "sha256": pSHA}, "url")},
				"to": str("Default folder for items without their own"), "resume_mode": pResumeMode}, "items"),
			run: runAddBatch},
		{Name: "hf_add",
			Description: "Hugging Face helper: looks up size and SHA-256 of files in a model repo, then queues them (verified on completion). Pin a commit with rev for files that must not change.",
			Schema: obj(map[string]any{"repo": str(`"owner/name"`), "paths": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "File paths inside the repo"},
				"rev": str("Branch, tag or commit (default main)"), "to": pTo}, "repo", "paths"),
			run: runHF},
		{Name: "list", ReadOnly: true,
			Description: "Your jobs with state and progress (compact).",
			Schema:      obj(map[string]any{"state": str("Only jobs in this state (queued, running, retrying, paused, done, failed, cancelled)")}), run: runList},
		{Name: "status", ReadOnly: true, Description: "One job in detail, including the last error or notice.",
			Schema: obj(map[string]any{"id": pID}, "id"), run: runStatus},
		{Name: "wait", ReadOnly: true,
			Description: "Block until the given jobs (default: all yours) are done, failed, cancelled or paused, or until timeout. Returns one summary line plus short job rows. Use this instead of polling list.",
			Schema: obj(map[string]any{"ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				"timeout": str(`Go duration, e.g. "10m", "1h" (default 10m, max 6h). If it times out, call wait again.`)}),
			run: runWait},
		{Name: "pause", Description: "Pause a job (partial data is kept).", Schema: obj(map[string]any{"id": pID}, "id"), run: simple("pause")},
		{Name: "resume", Description: "Resume a paused job.", Schema: obj(map[string]any{"id": pID}, "id"), run: simple("resume")},
		{Name: "cancel", Description: "Cancel a job and delete its partial file.", Schema: obj(map[string]any{"id": pID}, "id"), run: simple("cancel")},
		{Name: "retry", Description: "Retry a failed job, optionally with another resume mode.",
			Schema: obj(map[string]any{"id": pID, "resume_mode": pResumeMode}, "id"), run: runRetry},
		{Name: "relink",
			Description: "Continue a failed job from a new link to the same file (expired temporary links). Partial data is kept; with sha256 only the missing bytes are fetched.",
			Schema:      obj(map[string]any{"id": pID, "url": pURL, "sha256": pSHA, "resume_mode": pResumeMode}, "id", "url"), run: runRelink},
		{Name: "verify", ReadOnly: true, Description: "Recompute the SHA-256 of a finished file (returns only the hash).",
			Schema: obj(map[string]any{"id": pID}, "id"), run: runVerify},
		{Name: "folders", ReadOnly: true, Description: "Save folders you may download into (configured roots and pinned favorites), with labels usable as \"@Label\".",
			Schema: obj(map[string]any{}), run: runFolders},
		{Name: "ls", ReadOnly: true, Description: "List subfolders (and file names, if allowed) inside a save folder. Never shows file contents.",
			Schema: obj(map[string]any{"path": str("Folder; omit for the default save folder")}), run: runLs},
		{Name: "disk", ReadOnly: true, Description: "Free space on each save folder's drive.", Schema: obj(map[string]any{}), run: runDisk},
	}
}

func toolByName(name string) (tool, bool) {
	for _, t := range tools {
		if t.Name == name {
			return t, true
		}
	}
	return tool{}, false
}

func toolList() []map[string]any {
	var out []map[string]any
	for _, t := range tools {
		m := map[string]any{"name": t.Name, "description": t.Description, "inputSchema": t.Schema}
		ann := map[string]any{"readOnlyHint": t.ReadOnly, "openWorldHint": t.Name == "probe" || t.Name == "add" || t.Name == "add_batch" || t.Name == "hf_add" || t.Name == "relink"}
		if t.Name == "cancel" {
			ann["destructiveHint"] = true
		}
		m["annotations"] = ann
		out = append(out, m)
	}
	return out
}

// ---- helpers ----

func decode(args json.RawMessage, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(args)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("invalid arguments: %v", err)
	}
	return nil
}

func (s *Server) dispatch(ctx context.Context, name string, args []string, flags map[string]string) command.Result {
	for k, v := range flags {
		if v == "" {
			delete(flags, k)
		}
	}
	return s.D.Dispatch(ctx, command.Command{Name: name, Args: args, Flags: flags, Identity: s.ident()})
}

func resErr(r command.Result) error {
	if r.OK {
		return nil
	}
	return errors.New(r.Message)
}

// row is a compact job view for agents.
type row struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	State    string  `json:"state"`
	Kind     string  `json:"kind,omitempty"`
	Progress *int    `json:"pct,omitempty"`
	Size     int64   `json:"size,omitempty"`
	Done     int64   `json:"bytes,omitempty"`
	Speed    int64   `json:"bps,omitempty"`
	ETA      int64   `json:"eta_s,omitempty"`
	Dir      string  `json:"dir,omitempty"`
	Path     string  `json:"path,omitempty"`
	SHA256   string  `json:"sha256,omitempty"`
	Verified bool    `json:"verified,omitempty"`
	Commit   string  `json:"commit,omitempty"`
	Error    string  `json:"error,omitempty"`
	Notice   string  `json:"notice,omitempty"`
	Retry    *string `json:"next_retry,omitempty"`
}

func toRow(v engine.JobView, detail bool) row {
	r := row{ID: v.ID, Name: v.Name, State: string(v.State), Kind: v.Kind, Done: v.Downloaded, Speed: int64(v.Speed), ETA: int64(v.ETA), Error: v.Error}
	if v.ExpectedSize > 0 {
		r.Size = v.ExpectedSize
		p := int(v.Progress() * 100)
		if v.State == state.StateDone {
			p = 100
		}
		r.Progress = &p
	}
	if v.State == state.StateDone {
		r.Path, r.SHA256, r.Verified, r.Commit = v.FinalPath, v.SHA256, v.Verified, v.Commit
		r.Done, r.Speed, r.ETA = 0, 0, 0
	} else if detail {
		r.Dir = v.Dir
	}
	if detail {
		r.Notice = v.Notice
		if !v.NextRetry.IsZero() {
			t := v.NextRetry.UTC().Format(time.RFC3339)
			r.Retry = &t
		}
	}
	return r
}

func simple(name string) func(context.Context, *Server, json.RawMessage) (any, error) {
	return func(ctx context.Context, s *Server, args json.RawMessage) (any, error) {
		var a struct {
			ID string `json:"id"`
		}
		if err := decode(args, &a); err != nil {
			return nil, err
		}
		r := s.dispatch(ctx, name, []string{a.ID}, nil)
		if err := resErr(r); err != nil {
			return nil, err
		}
		return r.Message, nil
	}
}

// ---- tools ----

func runProbe(ctx context.Context, s *Server, args json.RawMessage) (any, error) {
	var a struct {
		URL string `json:"url"`
	}
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	r := s.dispatch(ctx, "probe", []string{a.URL}, nil)
	if err := resErr(r); err != nil {
		return nil, err
	}
	p, ok := r.Data.(*engine.ProbeResult)
	if !ok {
		return r.Message, nil
	}
	out := map[string]any{"kind": p.Kind, "verdict": p.Verdict, "filename": p.Filename}
	if p.Type != nil {
		out["type"] = p.Type.Description
	}
	if p.Size >= 0 {
		out["size"] = p.Size
	}
	if p.Kind == "file" {
		out["resumable"] = p.Resumable
	}
	if p.SHA256 != "" {
		out["sha256"] = p.SHA256
	}
	if len(p.Warnings) > 0 {
		out["warnings"] = p.Warnings
	}
	if p.Git != nil {
		out["git"] = map[string]any{"repo": p.Git.Repo.Owner + "/" + p.Git.Repo.Name, "host": p.Git.Repo.Host, "ref": p.Git.Repo.Ref, "git_installed": p.Git.GitInstalled}
	}
	if c := p.Contents; c != nil {
		cm := map[string]any{"summary": c.Summary}
		var entries []string
		for i, e := range c.Entries {
			if i >= 25 {
				break
			}
			name := e.Name
			if e.Dir && !strings.HasSuffix(name, "/") {
				name += "/"
			}
			if e.Size >= 0 && !e.Dir {
				name += " (" + policy.HumanBytes(e.Size) + ")"
			}
			entries = append(entries, name)
		}
		cm["entries"] = entries
		if more := len(c.Entries) - len(entries); more > 0 || c.Truncated {
			cm["more"] = true
		}
		out["contents"] = cm
	}
	return out, nil
}

type addArgs struct {
	URL        string `json:"url"`
	To         string `json:"to"`
	Name       string `json:"name"`
	SHA256     string `json:"sha256"`
	ResumeMode string `json:"resume_mode"`
	All        bool   `json:"all"`
}

func jobRef(j *state.Job) map[string]any {
	m := map[string]any{"id": j.ID, "name": j.Name, "dir": j.Dir}
	if j.Kind != "" {
		m["kind"] = j.Kind
	}
	return m
}

func (s *Server) addOne(ctx context.Context, a addArgs) (*state.Job, error) {
	r := s.dispatch(ctx, "add", []string{a.URL}, map[string]string{"to": a.To, "name": a.Name, "sha256": a.SHA256, "resume-mode": a.ResumeMode})
	if err := resErr(r); err != nil {
		return nil, err
	}
	j, _ := r.Data.(*state.Job)
	if j == nil {
		return nil, errors.New(r.Message)
	}
	return j, nil
}

func runAdd(ctx context.Context, s *Server, args json.RawMessage) (any, error) {
	var a addArgs
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	if a.All {
		r := s.dispatch(ctx, "probe", []string{a.URL}, nil)
		if err := resErr(r); err != nil {
			return nil, err
		}
		p, _ := r.Data.(*engine.ProbeResult)
		if p == nil || p.Kind != "folder" || p.Contents == nil {
			return nil, errors.New("all=true only works for web folder links; this link is not a folder listing")
		}
		var urls []batchItem
		for _, e := range p.Contents.Entries {
			if !e.Dir {
				urls = append(urls, batchItem{URL: e.URL})
			}
		}
		return s.batch(ctx, urls, a.To, a.ResumeMode), nil
	}
	j, err := s.addOne(ctx, a)
	if err != nil {
		return nil, err
	}
	return jobRef(j), nil
}

type batchItem struct {
	URL    string `json:"url"`
	To     string `json:"to"`
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

func (s *Server) batch(ctx context.Context, items []batchItem, defTo, mode string) map[string]any {
	var queued []map[string]any
	var failed []map[string]any
	for _, it := range items {
		to := it.To
		if to == "" {
			to = defTo
		}
		j, err := s.addOne(ctx, addArgs{URL: it.URL, To: to, Name: it.Name, SHA256: it.SHA256, ResumeMode: mode})
		if err != nil {
			failed = append(failed, map[string]any{"url": it.URL, "error": err.Error()})
			continue
		}
		queued = append(queued, jobRef(j))
	}
	out := map[string]any{"queued": queued}
	if len(failed) > 0 {
		out["failed"] = failed
	}
	return out
}

func runAddBatch(ctx context.Context, s *Server, args json.RawMessage) (any, error) {
	var a struct {
		Items      []batchItem `json:"items"`
		To         string      `json:"to"`
		ResumeMode string      `json:"resume_mode"`
	}
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	if len(a.Items) == 0 {
		return nil, errors.New("items is empty")
	}
	if len(a.Items) > 100 {
		return nil, errors.New("at most 100 items per call")
	}
	return s.batch(ctx, a.Items, a.To, a.ResumeMode), nil
}

func runHF(ctx context.Context, s *Server, args json.RawMessage) (any, error) {
	var a struct {
		Repo  string   `json:"repo"`
		Paths []string `json:"paths"`
		Rev   string   `json:"rev"`
		To    string   `json:"to"`
	}
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	r := s.dispatch(ctx, "hf", append([]string{a.Repo}, a.Paths...), map[string]string{"rev": a.Rev, "to": a.To})
	jobs, _ := r.Data.([]*state.Job)
	var queued []map[string]any
	for _, j := range jobs {
		queued = append(queued, jobRef(j))
	}
	if !r.OK && len(queued) == 0 {
		return nil, errors.New(r.Message)
	}
	out := map[string]any{"queued": queued}
	if !r.OK {
		out["message"] = r.Message
	}
	return out, nil
}

func runList(ctx context.Context, s *Server, args json.RawMessage) (any, error) {
	var a struct {
		State string `json:"state"`
	}
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	r := s.dispatch(ctx, "list", nil, nil)
	if err := resErr(r); err != nil {
		return nil, err
	}
	views, _ := r.Data.([]engine.JobView)
	rows := []row{}
	for _, v := range views {
		if a.State == "" || string(v.State) == a.State {
			rows = append(rows, toRow(v, false))
		}
	}
	return map[string]any{"summary": command.Summarize(views), "jobs": rows}, nil
}

func runStatus(ctx context.Context, s *Server, args json.RawMessage) (any, error) {
	var a struct {
		ID string `json:"id"`
	}
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	r := s.dispatch(ctx, "status", []string{a.ID}, nil)
	if err := resErr(r); err != nil {
		return nil, err
	}
	v, _ := r.Data.(engine.JobView)
	return toRow(v, true), nil
}

func runWait(ctx context.Context, s *Server, args json.RawMessage) (any, error) {
	var a struct {
		IDs     []string `json:"ids"`
		Timeout string   `json:"timeout"`
	}
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	timeout := 10 * time.Minute
	if a.Timeout != "" {
		d, err := time.ParseDuration(a.Timeout)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("bad timeout %q (use e.g. \"10m\")", a.Timeout)
		}
		timeout = d
	}
	if timeout > s.MaxWait {
		timeout = s.MaxWait
	}
	r := s.dispatch(ctx, "wait", a.IDs, map[string]string{"timeout": timeout.String()})
	views, _ := r.Data.([]engine.JobView)
	if !r.OK && views == nil {
		return nil, errors.New(r.Message)
	}
	rows := []row{}
	for _, v := range views {
		rows = append(rows, toRow(v, false))
	}
	return map[string]any{"finished": r.OK, "summary": r.Message, "jobs": rows}, nil
}

func runRetry(ctx context.Context, s *Server, args json.RawMessage) (any, error) {
	var a struct {
		ID         string `json:"id"`
		ResumeMode string `json:"resume_mode"`
	}
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	r := s.dispatch(ctx, "retry", []string{a.ID}, map[string]string{"resume-mode": a.ResumeMode})
	if err := resErr(r); err != nil {
		return nil, err
	}
	return r.Message, nil
}

func runRelink(ctx context.Context, s *Server, args json.RawMessage) (any, error) {
	var a struct {
		ID         string `json:"id"`
		URL        string `json:"url"`
		SHA256     string `json:"sha256"`
		ResumeMode string `json:"resume_mode"`
	}
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	r := s.dispatch(ctx, "relink", []string{a.ID, a.URL}, map[string]string{"sha256": a.SHA256, "resume-mode": a.ResumeMode})
	if err := resErr(r); err != nil {
		return nil, err
	}
	return r.Message, nil
}

func runVerify(ctx context.Context, s *Server, args json.RawMessage) (any, error) {
	var a struct {
		ID string `json:"id"`
	}
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	r := s.dispatch(ctx, "verify", []string{a.ID}, nil)
	if m, ok := r.Data.(map[string]any); ok {
		return m, nil
	}
	if err := resErr(r); err != nil {
		return nil, err
	}
	return r.Message, nil
}

func runFolders(ctx context.Context, s *Server, args json.RawMessage) (any, error) {
	var a struct{}
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	r := s.dispatch(ctx, "folders", nil, nil)
	if err := resErr(r); err != nil {
		return nil, err
	}
	return r.Data, nil
}

func runLs(ctx context.Context, s *Server, args json.RawMessage) (any, error) {
	var a struct {
		Path string `json:"path"`
	}
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	var argv []string
	if a.Path != "" {
		argv = []string{a.Path}
	}
	r := s.dispatch(ctx, "ls", argv, nil)
	if err := resErr(r); err != nil {
		return nil, err
	}
	ents, _ := r.Data.([]policy.Entry)
	var dirs, files []string
	for _, e := range ents {
		if e.IsDir {
			dirs = append(dirs, e.Name)
		} else {
			files = append(files, e.Name)
		}
	}
	out := map[string]any{"folders": dirs}
	if files != nil {
		out["files"] = files
	}
	return out, nil
}

func runDisk(ctx context.Context, s *Server, args json.RawMessage) (any, error) {
	var a struct{}
	if err := decode(args, &a); err != nil {
		return nil, err
	}
	r := s.dispatch(ctx, "disk", nil, nil)
	if err := resErr(r); err != nil {
		return nil, err
	}
	return r.Data, nil
}
