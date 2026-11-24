package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lintlabbuild/lint-rdl/internal/command"
	"github.com/lintlabbuild/lint-rdl/internal/engine"
	"github.com/lintlabbuild/lint-rdl/internal/policy"
	"github.com/lintlabbuild/lint-rdl/internal/state"
	"github.com/lintlabbuild/lint-rdl/testserver"
)

// client is a minimal MCP client over pipes.
type client struct {
	t      *testing.T
	in     io.WriteCloser
	mu     sync.Mutex
	nextID int
	wait   map[string]chan map[string]any
	calls  int
	raw    []string // every line the server wrote
	done   chan struct{}
}

func newClient(t *testing.T, s *Server) *client {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	c := &client{t: t, in: inW, wait: map[string]chan map[string]any{}, done: make(chan struct{})}
	go func() {
		s.Serve(context.Background(), inR, outW)
		outW.Close()
	}()
	go func() {
		defer close(c.done)
		sc := bufio.NewScanner(outR)
		sc.Buffer(make([]byte, 1<<20), 16<<20)
		for sc.Scan() {
			line := sc.Text()
			c.mu.Lock()
			c.raw = append(c.raw, line)
			c.mu.Unlock()
			var m map[string]any
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				t.Errorf("server wrote non-JSON to stdout: %q", line)
				continue
			}
			id := fmt.Sprint(m["id"])
			c.mu.Lock()
			ch := c.wait[id]
			c.mu.Unlock()
			if ch != nil {
				ch <- m
			}
		}
	}()
	t.Cleanup(func() { inW.Close(); <-c.done })
	return c
}

func (c *client) send(v any) {
	b, _ := json.Marshal(v)
	c.in.Write(append(b, '\n'))
}

func (c *client) request(method string, params any) (int, chan map[string]any) {
	c.mu.Lock()
	c.nextID++
	id := c.nextID
	ch := make(chan map[string]any, 1)
	c.wait[fmt.Sprint(id)] = ch
	c.mu.Unlock()
	c.send(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	return id, ch
}

func (c *client) call(method string, params any) map[string]any {
	c.t.Helper()
	_, ch := c.request(method, params)
	select {
	case m := <-ch:
		return m
	case <-time.After(60 * time.Second):
		c.t.Fatalf("no response to %s", method)
		return nil
	}
}

// tool calls a tool and returns (decoded text, isError).
func (c *client) tool(name string, args any) (any, bool) {
	c.t.Helper()
	c.calls++
	m := c.call("tools/call", map[string]any{"name": name, "arguments": args})
	if e, ok := m["error"]; ok {
		c.t.Fatalf("%s: protocol error %v", name, e)
	}
	res := m["result"].(map[string]any)
	text := res["content"].([]any)[0].(map[string]any)["text"].(string)
	isErr, _ := res["isError"].(bool)
	var v any
	if json.Unmarshal([]byte(text), &v) != nil {
		v = text
	}
	return v, isErr
}

type fixture struct {
	disp *command.Dispatcher
	root string
}

func setup(t *testing.T) fixture {
	root, _ := policy.RealPath(t.TempDir())
	os.Mkdir(filepath.Join(root, "models"), 0o755)
	j, _ := state.OpenJournal(filepath.Join(t.TempDir(), "jobs"))
	up := &policy.URLPolicy{AllowPrivate: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	paths := &policy.PathPolicy{Roots: []string{root}}
	m, err := engine.New(engine.Options{URLPolicy: up, Paths: paths, Journal: j, Disk: &policy.DiskGuard{}, MaxParallel: 4, ChunkSize: 64 << 10, Backoff: []time.Duration{10 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	m.Start()
	t.Cleanup(m.Close)
	return fixture{disp: &command.Dispatcher{M: m, Paths: paths, URLs: up, Limits: command.Limits{CommandsPerMinute: 1000}}, root: root}
}

func initialized(t *testing.T, f fixture) *client {
	c := newClient(t, &Server{D: f.disp, Name: "rdl", Version: "test"})
	m := c.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "clientInfo": map[string]any{"name": "Claude Code"}, "capabilities": map[string]any{}})
	res := m["result"].(map[string]any)
	if res["protocolVersion"] != "2025-06-18" {
		t.Fatalf("version %v", res["protocolVersion"])
	}
	c.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	return c
}

func TestProtocolBasics(t *testing.T) {
	f := setup(t)
	c := initialized(t, f)
	m := c.call("tools/list", map[string]any{})
	list := m["result"].(map[string]any)["tools"].([]any)
	names := map[string]bool{}
	for _, x := range list {
		tm := x.(map[string]any)
		names[tm["name"].(string)] = true
		if tm["inputSchema"].(map[string]any)["type"] != "object" {
			t.Fatalf("bad schema for %v", tm["name"])
		}
	}
	for _, n := range []string{"probe", "add", "add_batch", "hf_add", "list", "status", "wait", "pause", "resume", "cancel", "retry", "relink", "verify", "folders", "ls", "disk"} {
		if !names[n] {
			t.Errorf("missing tool %s", n)
		}
	}
	for n := range names {
		if strings.Contains(n, "power") || n == "when_done" {
			t.Fatalf("power tool exposed to agents: %s", n)
		}
	}
	if m := c.call("ping", nil); m["error"] != nil {
		t.Fatal("ping failed")
	}
	if m := c.call("resources/list", nil); m["error"].(map[string]any)["code"].(float64) != codeMethodNotFound {
		t.Fatal("unknown method should be -32601")
	}
	if m := c.call("tools/call", map[string]any{"name": "nope"}); m["error"] == nil {
		t.Fatal("unknown tool accepted")
	}
	if v, isErr := c.tool("add", map[string]any{"url": "http://x", "bogus": 1}); !isErr || !strings.Contains(fmt.Sprint(v), "unknown field") {
		t.Fatalf("unknown argument accepted: %v", v)
	}
	if v, isErr := c.tool("add", map[string]any{"url": "http://169.254.169.254/latest"}); !isErr || !strings.Contains(fmt.Sprint(v), "not a public address") {
		t.Fatalf("SSRF not refused: %v", v)
	}
	if v, isErr := c.tool("add", map[string]any{"url": "https://www.youtube.com/watch?v=x"}); !isErr || !strings.Contains(fmt.Sprint(v), "streaming") {
		t.Fatalf("streaming not refused: %v", v)
	}
	if v, isErr := c.tool("add", map[string]any{"url": "https://example.com/x", "to": "../"}); !isErr || !strings.Contains(fmt.Sprint(v), "path policy") {
		t.Fatalf("path escape not refused: %v", v)
	}
	// Agent identity comes from clientInfo.
	if c.calls < 1 || f.disp == nil {
		t.Fatal()
	}
}

// TestModelSetInFewCalls is the spec's phase 4 "done" check: an agent
// downloads a 15-file set in <= 5 tool calls, every file SHA-256 verified.
func TestModelSetInFewCalls(t *testing.T) {
	f := setup(t)
	type file struct {
		srv  *testserver.Server
		data []byte
	}
	var files []file
	var items []map[string]any
	for i := 0; i < 15; i++ {
		data := testserver.Content(50<<10+i*1000, int64(i))
		srv := testserver.New(data, testserver.Options{CutEvery: 20 << 10}) // flaky links
		t.Cleanup(srv.Close)
		files = append(files, file{srv, data})
		items = append(items, map[string]any{"url": srv.FileURL(), "name": fmt.Sprintf("part-%02d.safetensors", i), "sha256": testserver.SHA256(data), "to": "models"})
	}
	c := initialized(t, f)
	c.calls = 0

	v, isErr := c.tool("add_batch", map[string]any{"items": items})
	if isErr {
		t.Fatalf("add_batch: %v", v)
	}
	if q := v.(map[string]any)["queued"].([]any); len(q) != 15 {
		t.Fatalf("queued %d", len(q))
	}
	v, isErr = c.tool("wait", map[string]any{"timeout": "2m"})
	if isErr || v.(map[string]any)["finished"] != true || v.(map[string]any)["summary"] != "15 done" {
		t.Fatalf("wait: %v", v)
	}
	v, _ = c.tool("list", map[string]any{"state": "done"})
	jobs := v.(map[string]any)["jobs"].([]any)
	if len(jobs) != 15 {
		t.Fatalf("done jobs %d", len(jobs))
	}
	for _, j := range jobs {
		jm := j.(map[string]any)
		if jm["verified"] != true || !strings.HasPrefix(jm["path"].(string), filepath.Join(f.root, "models")) {
			t.Fatalf("not verified or wrong folder: %v", jm)
		}
	}
	if c.calls > 5 {
		t.Fatalf("took %d tool calls, want <= 5", c.calls)
	}
	t.Logf("15 files in %d tool calls", c.calls)
}

func TestCancellationAndOwnership(t *testing.T) {
	f := setup(t)
	data := testserver.Content(1<<20, 1)
	srv := testserver.New(data, testserver.Options{StallAfter: 1000})
	t.Cleanup(srv.Close)

	// A job added by someone else (the owner at the PC) is invisible to the agent.
	r := f.disp.Dispatch(context.Background(), command.Command{Name: "add", Args: []string{srv.FileURL()}, Identity: command.Identity{ID: "cli:me", Via: "cli", Role: command.RoleOwner}})
	if !r.OK {
		t.Fatal(r.Message)
	}
	ownerJob := r.Data.(*state.Job).ID

	c := initialized(t, f)
	if v, isErr := c.tool("cancel", map[string]any{"id": ownerJob}); !isErr || !strings.Contains(fmt.Sprint(v), "someone else") {
		t.Fatalf("agent cancelled the owner's job: %v", v)
	}
	if v, _ := c.tool("list", map[string]any{}); len(v.(map[string]any)["jobs"].([]any)) != 0 {
		t.Fatalf("agent sees the owner's jobs: %v", v)
	}

	// A long wait can be cancelled by the client; no response is sent for it.
	v, _ := c.tool("add", map[string]any{"url": srv.FileURL() + "?copy=1"})
	id := v.(map[string]any)["id"].(string)
	reqID, ch := c.request("tools/call", map[string]any{"name": "wait", "arguments": map[string]any{"ids": []string{id}, "timeout": "1h"}})
	time.Sleep(100 * time.Millisecond)
	c.send(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": reqID}})
	select {
	case m := <-ch:
		t.Fatalf("cancelled request got a response: %v", m)
	case <-time.After(300 * time.Millisecond):
	}
	// The server still answers afterwards.
	if v, isErr := c.tool("status", map[string]any{"id": id}); isErr || v.(map[string]any)["state"] == "" {
		t.Fatalf("status after cancel: %v", v)
	}
}

func TestProbeAndFolders(t *testing.T) {
	f := setup(t)
	data := testserver.Content(4096, 3)
	srv := testserver.New(data, testserver.Options{})
	t.Cleanup(srv.Close)
	c := initialized(t, f)
	v, isErr := c.tool("probe", map[string]any{"url": srv.FileURL()})
	if isErr {
		t.Fatalf("probe: %v", v)
	}
	p := v.(map[string]any)
	if p["resumable"] != "YES" || p["size"].(float64) != 4096 || p["filename"] != "file.bin" {
		t.Fatalf("%v", p)
	}
	v, _ = c.tool("folders", map[string]any{})
	if !strings.Contains(fmt.Sprint(v), f.root) {
		t.Fatalf("folders: %v", v)
	}
	v, _ = c.tool("ls", map[string]any{})
	if !strings.Contains(fmt.Sprint(v), "models") {
		t.Fatalf("ls: %v", v)
	}
}
