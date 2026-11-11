package command

import (
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lintlabbuild/lint-rdl/internal/engine"
	"github.com/lintlabbuild/lint-rdl/internal/policy"
	"github.com/lintlabbuild/lint-rdl/internal/state"
	"github.com/lintlabbuild/lint-rdl/testserver"
)

func setup(t *testing.T) (*Dispatcher, *testserver.Server) {
	root, _ := policy.RealPath(t.TempDir())
	j, _ := state.OpenJournal(filepath.Join(t.TempDir(), "jobs"))
	up := &policy.URLPolicy{AllowPrivate: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	paths := &policy.PathPolicy{Roots: []string{root}}
	m, err := engine.New(engine.Options{URLPolicy: up, Paths: paths, Journal: j, Disk: &policy.DiskGuard{}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(m.Close)
	srv := testserver.New(testserver.Content(4096, 1), testserver.Options{})
	t.Cleanup(srv.Close)
	return &Dispatcher{M: m, Paths: paths, URLs: up}, srv
}

func TestRolesAndOwnership(t *testing.T) {
	d, srv := setup(t)
	ctx := context.Background()
	alice := Identity{ID: "telegram:1", Via: "telegram", Role: RoleUser}
	bob := Identity{ID: "telegram:2", Via: "telegram", Role: RoleUser}
	agent := Identity{ID: "mcp:a", Via: "mcp", Role: RoleAgent}
	owner := Identity{ID: "cli:me", Via: "cli", Role: RoleOwner}

	r := d.Dispatch(ctx, Command{Name: "add", Args: []string{srv.FileURL()}, Identity: alice})
	if !r.OK {
		t.Fatal(r.Message)
	}
	id := r.Data.(*state.Job).ID
	if r := d.Dispatch(ctx, Command{Name: "cancel", Args: []string{id}, Identity: bob}); r.OK {
		t.Fatal("bob cancelled alice's job")
	}
	if r := d.Dispatch(ctx, Command{Name: "list", Identity: bob}); len(r.Data.([]engine.JobView)) != 0 {
		t.Fatal("bob sees alice's jobs")
	}
	if r := d.Dispatch(ctx, Command{Name: "status", Args: []string{id}, Identity: owner}); !r.OK {
		t.Fatal(r.Message)
	}
	if r := d.Dispatch(ctx, Command{Name: "power", Args: []string{"shutdown"}, Identity: agent}); r.OK || !strings.Contains(r.Message, ErrDenied.Error()) {
		t.Fatalf("agent power: %v", r.Message)
	}
	if r := d.Dispatch(ctx, Command{Name: "when-done", Args: []string{"shutdown"}, Identity: alice}); r.OK {
		t.Fatal("user power allowed")
	}
	d.Limits.AgentCanPower = true
	if !d.Allowed(RoleAgent, "power") {
		t.Fatal("agent_can_power not honoured")
	}
	if r := d.Dispatch(ctx, Command{Name: "whoami", Identity: Identity{}}); r.OK {
		t.Fatal("empty identity accepted")
	}
	if r := d.Dispatch(ctx, Command{Name: "roots", Identity: owner}); r.OK {
		t.Fatal("config command reachable through dispatcher")
	}
}

func TestWaitSummary(t *testing.T) {
	d, srv := setup(t)
	d.M.Start()
	ctx := context.Background()
	me := Identity{ID: "mcp:a", Via: "mcp", Role: RoleAgent}
	r := d.Dispatch(ctx, Command{Name: "add", Args: []string{srv.FileURL()}, Identity: me})
	if !r.OK {
		t.Fatal(r.Message)
	}
	r = d.Dispatch(ctx, Command{Name: "wait", Flags: map[string]string{"timeout": "20s"}, Identity: me})
	if !r.OK || r.Message != "1 done" {
		t.Fatalf("%v %q", r.OK, r.Message)
	}
}

func TestRateLimit(t *testing.T) {
	d, _ := setup(t)
	d.Limits.CommandsPerMinute = 3
	me := Identity{ID: "web:x", Via: "web", Role: RoleUser}
	var last Result
	for i := 0; i < 5; i++ {
		last = d.Dispatch(context.Background(), Command{Name: "whoami", Identity: me})
	}
	if last.OK {
		t.Fatal("rate limit not enforced")
	}
}

func TestPolicyErrorsSurface(t *testing.T) {
	d, _ := setup(t)
	me := Identity{ID: "mcp:a", Via: "mcp", Role: RoleAgent}
	r := d.Dispatch(context.Background(), Command{Name: "add", Args: []string{"http://169.254.169.254/"}, Identity: me})
	if r.OK || !strings.Contains(r.Message, policy.ErrBlocked.Error()) {
		t.Fatalf("%v", r.Message)
	}
	r = d.Dispatch(context.Background(), Command{Name: "add", Args: []string{"https://example.com/x"}, Flags: map[string]string{"to": "../../"}, Identity: me})
	if r.OK || !strings.Contains(r.Message, "path policy") {
		t.Fatalf("%v", r.Message)
	}
}
