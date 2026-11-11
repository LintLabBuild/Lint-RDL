package engine

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lintlabbuild/lint-rdl/internal/state"
	"github.com/lintlabbuild/lint-rdl/testserver"
)

// edges simulates retries landing on different CDN edges: request 1 cuts
// at 300K; request 2 hits an edge that ignores ranges and cuts at 200K;
// request 3 honours ranges and finishes.
func edges(n int) (bool, int64) {
	switch n {
	case 1:
		return false, 300 << 10
	case 2:
		return true, 200 << 10
	}
	return false, 0
}

func rangeOf(srv *testserver.Server, n int) string {
	l := srv.Log[n-1]
	i := strings.Index(l, `range="`)
	return l[i+7 : strings.Index(l[i+7:], `"`)+i+7]
}

func TestRatchetKeepsProgress(t *testing.T) {
	content := testserver.Content(1<<20, 7)
	v, srv, _ := run(t, testserver.Options{PerRequest: edges}, len(content), nil)
	checkFile(t, v, content)
	// Request 3 continues from 300K (best point), not 200K or 0.
	if got := rangeOf(srv, 3); got != "bytes=307200-" {
		t.Fatalf("request 3 asked %q; ratchet should keep the 300K already saved", got)
	}
}

func TestRestartModeWipes(t *testing.T) {
	content := testserver.Content(1<<20, 7)
	v, srv, _ := run(t, testserver.Options{PerRequest: edges}, len(content), func(e *env) { e.opts.ResumeMode = ModeRestart })
	checkFile(t, v, content)
	if got := rangeOf(srv, 3); got != "bytes=204800-" {
		t.Fatalf("request 3 asked %q; restart mode wipes at request 2 and keeps only its 200K", got)
	}
}

func TestMissingOnlyStopsThenRatchet(t *testing.T) {
	content := testserver.Content(1<<20, 7)
	srv := testserver.New(content, testserver.Options{PerRequest: edges})
	defer srv.Close()
	e := newEnv(t)
	e.opts.ResumeMode = ModeMissingOnly
	m := e.manager(t)
	defer m.Close()
	m.Start()
	job, _ := m.Add(AddRequest{URL: srv.FileURL(), SHA256: testserver.SHA256(content)})
	v := waitDone(t, m, job.ID, 10*time.Second)
	if v.State != state.StateFailed || !strings.Contains(v.Error, "missing-only") || v.Written != 300<<10 {
		t.Fatalf("state %s written %d err %q", v.State, v.Written, v.Error)
	}
	if fi, err := os.Stat(v.PartPath); err != nil || fi.Size() != 300<<10 {
		t.Fatal("partial file must be kept")
	}
	if err := m.SetResumeMode(job.ID, ModeRatchet); err != nil {
		t.Fatal(err)
	}
	if err := m.Retry(job.ID); err != nil {
		t.Fatal(err)
	}
	v = waitDone(t, m, job.ID, 10*time.Second)
	checkFile(t, v, content)
}

func TestRatchetDetectsChangedFile(t *testing.T) {
	// No ETag/Last-Modified and no ranges: only the prefix hash can tell
	// that the file changed between attempts.
	content := testserver.Content(512<<10, 7)
	srv := testserver.New(content, testserver.Options{NoValidators: true, IgnoreRange: true, ChangeAfter: 1,
		PerRequest: func(n int) (bool, int64) {
			if n == 1 {
				return true, 200 << 10
			}
			return true, 0
		}})
	defer srv.Close()
	e := newEnv(t)
	m := e.manager(t)
	defer m.Close()
	m.Start()
	job, _ := m.Add(AddRequest{URL: srv.FileURL()})
	v := waitDone(t, m, job.ID, 10*time.Second)
	checkFile(t, v, srv.CurrentContent())
	if !strings.Contains(strings.Join(srv.Log, "\n"), "GET") || srv.Gets() < 3 {
		t.Fatalf("expected a verify attempt and a clean restart, got %d requests", srv.Gets())
	}
}

func TestRatchetWithGzip(t *testing.T) {
	content := testserver.Content(256<<10, 7)
	v, _, _ := run(t, testserver.Options{Gzip: true, PerRequest: func(n int) (bool, int64) {
		if n == 1 {
			return false, 100 << 10 // cut the compressed stream
		}
		return false, 0
	}}, len(content), nil)
	checkFile(t, v, content)
}

func TestRelinkExpiredLink(t *testing.T) {
	content := testserver.Content(1<<20, 7)
	old := testserver.New(content, testserver.Options{CutEvery: 300 << 10})
	defer old.Close()
	fresh := testserver.New(content, testserver.Options{})
	defer fresh.Close()
	e := newEnv(t)
	m := e.manager(t)
	defer m.Close()
	m.Start()
	job, _ := m.Add(AddRequest{URL: old.FileURL()})
	for old.Gets() < 1 {
		time.Sleep(time.Millisecond)
	}
	old.Update(func(o *testserver.Options) { o.Status = 404 }) // the temporary link expired
	v := waitDone(t, m, job.ID, 10*time.Second)
	if v.State != state.StateFailed || !strings.Contains(v.Error, "rdl relink") || v.Written == 0 {
		t.Fatalf("state %s written %d err %q", v.State, v.Written, v.Error)
	}
	if err := m.Relink(job.ID, fresh.URL+"/model.safetensors", ""); err != nil {
		t.Fatal(err)
	}
	v = waitDone(t, m, job.ID, 10*time.Second)
	checkFile(t, v, content)
	// No SHA-256 known: the new server must re-send the saved part first
	// (no Range on the first request) so it can be verified.
	if !strings.Contains(fresh.Log[0], `GET range=""`) {
		t.Fatalf("first request to the new link should verify, got %s", fresh.Log[0])
	}
}

func TestRelinkWithKnownHashUsesRange(t *testing.T) {
	content := testserver.Content(1<<20, 7)
	old := testserver.New(content, testserver.Options{CutEvery: 300 << 10})
	defer old.Close()
	fresh := testserver.New(content, testserver.Options{})
	defer fresh.Close()
	e := newEnv(t)
	m := e.manager(t)
	defer m.Close()
	m.Start()
	job, _ := m.Add(AddRequest{URL: old.FileURL(), SHA256: testserver.SHA256(content)})
	for old.Gets() < 1 {
		time.Sleep(time.Millisecond)
	}
	old.Update(func(o *testserver.Options) { o.Status = 410 })
	waitDone(t, m, job.ID, 10*time.Second)
	if err := m.Relink(job.ID, fresh.FileURL(), ""); err != nil {
		t.Fatal(err)
	}
	v := waitDone(t, m, job.ID, 10*time.Second)
	checkFile(t, v, content)
	if strings.Contains(fresh.Log[0], `GET range=""`) {
		t.Fatalf("with a known SHA-256 the new link should only send the missing bytes: %s", fresh.Log[0])
	}
}

func TestProbeMissingFile(t *testing.T) {
	srv := testserver.New([]byte("x"), testserver.Options{Status: 404, HEADForbidden: false})
	defer srv.Close()
	srv.Update(func(o *testserver.Options) { o.Status = 404 })
	e := newEnv(t)
	m := e.manager(t)
	defer m.Close()
	r, err := m.Probe(context.Background(), srv.URL+"/nothing-here.bin")
	if err != nil || !strings.Contains(r.Verdict, "doesn't exist") {
		t.Fatalf("%v %+v", err, r)
	}
}
