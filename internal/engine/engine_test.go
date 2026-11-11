package engine

import (
	"bytes"
	"context"
	"errors"
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lintlabbuild/lint-rdl/internal/policy"
	"github.com/lintlabbuild/lint-rdl/internal/state"
	"github.com/lintlabbuild/lint-rdl/testserver"
)

type env struct {
	root    string
	stateD  string
	journal *state.Journal
	opts    Options
}

func newEnv(t *testing.T) *env {
	t.Helper()
	root := t.TempDir()
	root, _ = policy.RealPath(root)
	stateD := t.TempDir()
	j, err := state.OpenJournal(filepath.Join(stateD, "jobs"))
	if err != nil {
		t.Fatal(err)
	}
	up := &policy.URLPolicy{AllowPrivate: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	return &env{
		root: root, stateD: stateD, journal: j,
		opts: Options{
			URLPolicy:     up,
			Paths:         &policy.PathPolicy{Roots: []string{root}},
			Disk:          &policy.DiskGuard{MinFree: 0},
			Journal:       j,
			ChunkSize:     64 << 10,
			Backoff:       []time.Duration{5 * time.Millisecond},
			StallTimeout:  2 * time.Second,
			DiskPollEvery: 20 * time.Millisecond,
			RenameRetries: 2,
		},
	}
}

func (e *env) manager(t *testing.T) *Manager {
	t.Helper()
	m, err := New(e.opts)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func waitDone(t *testing.T, m *Manager, id string, d time.Duration) JobView {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	vs, err := m.Wait(ctx, id)
	if err != nil {
		v, _ := m.Get(id)
		t.Fatalf("wait: %v (state %s, err %q)", err, v.State, v.Error)
	}
	return vs[0]
}

func checkFile(t *testing.T, v JobView, want []byte) {
	t.Helper()
	if v.State != state.StateDone {
		t.Fatalf("state = %s, error = %q", v.State, v.Error)
	}
	got, err := os.ReadFile(v.FinalPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("content mismatch: got %d bytes, want %d", len(got), len(want))
	}
	if v.SHA256 != testserver.SHA256(want) {
		t.Fatalf("sha256 = %s, want %s", v.SHA256, testserver.SHA256(want))
	}
	if _, err := os.Stat(v.PartPath); !os.IsNotExist(err) {
		t.Fatalf("part file still exists: %v", err)
	}
}

func run(t *testing.T, o testserver.Options, size int, mod func(*env)) (JobView, *testserver.Server, *Manager) {
	t.Helper()
	content := testserver.Content(size, 7)
	srv := testserver.New(content, o)
	t.Cleanup(srv.Close)
	e := newEnv(t)
	if mod != nil {
		mod(e)
	}
	m := e.manager(t)
	t.Cleanup(m.Close)
	m.Start()
	job, err := m.Add(AddRequest{URL: srv.FileURL(), SHA256: testserver.SHA256(content)})
	if err != nil {
		t.Fatal(err)
	}
	return waitDone(t, m, job.ID, 30*time.Second), srv, m
}

func TestPlainDownload(t *testing.T) {
	content := testserver.Content(1<<20, 7)
	v, _, _ := run(t, testserver.Options{}, len(content), nil)
	checkFile(t, v, content)
	if !v.Verified {
		t.Fatal("expected verified")
	}
}

func TestResumeAfterCuts(t *testing.T) {
	content := testserver.Content(1<<20, 7)
	v, srv, _ := run(t, testserver.Options{CutEvery: 100 << 10}, len(content), nil)
	checkFile(t, v, content)
	if srv.Gets() < 10 {
		t.Fatalf("expected many resumed requests, got %d", srv.Gets())
	}
	for _, l := range srv.Log[1:] {
		if !strings.Contains(l, "range=\"bytes=") {
			t.Fatalf("resume request without Range: %s", l)
		}
	}
}

func TestServerIgnoresRangeRestartsFromZero(t *testing.T) {
	content := testserver.Content(512<<10, 7)
	srv := testserver.New(content, testserver.Options{CutEvery: 200 << 10})
	defer srv.Close()
	e := newEnv(t)
	m := e.manager(t)
	defer m.Close()
	m.Start()
	job, _ := m.Add(AddRequest{URL: srv.FileURL(), SHA256: testserver.SHA256(content)})
	// Let a partial arrive, then switch the server to ignore ranges and stop cutting.
	deadline := time.Now().Add(5 * time.Second)
	for srv.Gets() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	srv.Update(func(o *testserver.Options) { o.IgnoreRange = true; o.CutEvery = 0 })
	v := waitDone(t, m, job.ID, 20*time.Second)
	checkFile(t, v, content)
}

func TestWrongContentRangeNoCuts(t *testing.T) {
	content := testserver.Content(512<<10, 7)
	srv := testserver.New(content, testserver.Options{WrongContentRange: true, CutEvery: 200 << 10})
	defer srv.Close()
	e := newEnv(t)
	m := e.manager(t)
	defer m.Close()
	m.Start()
	job, _ := m.Add(AddRequest{URL: srv.FileURL(), SHA256: testserver.SHA256(content)})
	for srv.Gets() < 3 {
		time.Sleep(time.Millisecond)
	}
	srv.Update(func(o *testserver.Options) { o.CutEvery = 0 })
	v := waitDone(t, m, job.ID, 20*time.Second)
	checkFile(t, v, content)
	// The server answers ranges wrongly, so rdl stops asking for them and
	// the ratchet verifies the saved part instead of wiping it.
	if !v.RangeBroken || !strings.Contains(v.Notice, "verified") {
		t.Fatalf("expected ratchet verification, got notice %q", v.Notice)
	}
}

func TestFileChangedOnServer(t *testing.T) {
	content := testserver.Content(512<<10, 7)
	srv := testserver.New(content, testserver.Options{CutEvery: 200 << 10, ChangeAfter: 1})
	defer srv.Close()
	e := newEnv(t)
	m := e.manager(t)
	defer m.Close()
	m.Start()
	job, _ := m.Add(AddRequest{URL: srv.FileURL()})
	for srv.Gets() < 2 {
		time.Sleep(time.Millisecond)
	}
	srv.Update(func(o *testserver.Options) { o.CutEvery = 0 })
	v := waitDone(t, m, job.ID, 20*time.Second)
	checkFile(t, v, srv.CurrentContent())
	if !strings.Contains(v.Notice, "changed") {
		t.Fatalf("expected 'file changed' notice, got %q", v.Notice)
	}
}

func TestNoValidatorsResumesBySize(t *testing.T) {
	content := testserver.Content(512<<10, 7)
	v, _, _ := run(t, testserver.Options{NoValidators: true, CutEvery: 100 << 10}, len(content), nil)
	checkFile(t, v, content)
}

func TestWeakETagUsesLastModified(t *testing.T) {
	content := testserver.Content(512<<10, 7)
	v, srv, _ := run(t, testserver.Options{WeakETag: true, CutEvery: 100 << 10}, len(content), nil)
	checkFile(t, v, content)
	for _, l := range srv.Log[1:] {
		if strings.Contains(l, `if-range="W/`) {
			t.Fatalf("weak ETag used in If-Range: %s", l)
		}
	}
}

func TestGzipTransfer(t *testing.T) {
	content := testserver.Content(256<<10, 7)
	v, _, _ := run(t, testserver.Options{Gzip: true}, len(content), nil)
	checkFile(t, v, content)
	if v.Resumable {
		t.Fatal("gzip transfer must not be marked resumable")
	}
}

func TestNoContentLength(t *testing.T) {
	content := testserver.Content(256<<10, 7)
	v, _, _ := run(t, testserver.Options{NoLength: true}, len(content), nil)
	checkFile(t, v, content)
}

func TestRetryAfter(t *testing.T) {
	content := testserver.Content(64<<10, 7)
	start := time.Now()
	v, _, _ := run(t, testserver.Options{BusyFirst: 1}, len(content), nil)
	checkFile(t, v, content)
	if time.Since(start) < 900*time.Millisecond {
		t.Fatal("Retry-After was not honoured")
	}
}

func TestHTMLErrorPageFails(t *testing.T) {
	v, _, _ := run(t, testserver.Options{HTMLError: true}, 1000, nil)
	if v.State != state.StateFailed || !strings.Contains(v.Error, "web page") {
		t.Fatalf("state %s err %q", v.State, v.Error)
	}
	entries, _ := os.ReadDir(filepath.Dir(v.PartPath))
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".part") {
			t.Fatalf("unexpected file %s", e.Name())
		}
	}
}

func Test404Fails(t *testing.T) {
	v, _, _ := run(t, testserver.Options{Status: 404}, 1000, nil)
	if v.State != state.StateFailed {
		t.Fatalf("state %s", v.State)
	}
}

func TestMultipartNotResumed(t *testing.T) {
	content := testserver.Content(256<<10, 7)
	srv := testserver.New(content, testserver.Options{Multipart: true, CutEvery: 100 << 10})
	defer srv.Close()
	e := newEnv(t)
	m := e.manager(t)
	defer m.Close()
	m.Start()
	job, _ := m.Add(AddRequest{URL: srv.FileURL(), SHA256: testserver.SHA256(content)})
	for srv.Gets() < 2 {
		time.Sleep(time.Millisecond)
	}
	srv.Update(func(o *testserver.Options) { o.CutEvery = 0 })
	v := waitDone(t, m, job.ID, 20*time.Second)
	checkFile(t, v, content)
}

func TestStallReconnects(t *testing.T) {
	content := testserver.Content(256<<10, 7)
	v, _, _ := run(t, testserver.Options{StallAfter: 100 << 10}, len(content), func(e *env) {
		e.opts.StallTimeout = 200 * time.Millisecond
	})
	checkFile(t, v, content)
}

func TestSignedURLExpiry(t *testing.T) {
	content := testserver.Content(512<<10, 7)
	srv := testserver.New(content, testserver.Options{ExpireAfterBytes: 150 << 10})
	defer srv.Close()
	e := newEnv(t)
	m := e.manager(t)
	defer m.Close()
	m.Start()
	job, err := m.Add(AddRequest{URL: srv.URL + "/sign", SHA256: testserver.SHA256(content), Name: "file.bin"})
	if err != nil {
		t.Fatal(err)
	}
	v := waitDone(t, m, job.ID, 20*time.Second)
	checkFile(t, v, content)
}

func TestRedirectFollowed(t *testing.T) {
	content := testserver.Content(64<<10, 7)
	srv := testserver.New(content, testserver.Options{})
	defer srv.Close()
	e := newEnv(t)
	m := e.manager(t)
	defer m.Close()
	m.Start()
	job, _ := m.Add(AddRequest{URL: srv.URL + "/redirect"})
	v := waitDone(t, m, job.ID, 10*time.Second)
	checkFile(t, v, content)
	if !strings.HasSuffix(v.FinalURL, "/file.bin") {
		t.Fatalf("final url %s", v.FinalURL)
	}
}

func TestChecksumMismatchFails(t *testing.T) {
	content := testserver.Content(64<<10, 7)
	srv := testserver.New(content, testserver.Options{})
	defer srv.Close()
	e := newEnv(t)
	m := e.manager(t)
	defer m.Close()
	m.Start()
	job, _ := m.Add(AddRequest{URL: srv.FileURL(), SHA256: strings.Repeat("ab", 32)})
	v := waitDone(t, m, job.ID, 10*time.Second)
	if v.State != state.StateFailed || !strings.Contains(v.Error, "SHA-256 mismatch") {
		t.Fatalf("state %s err %q", v.State, v.Error)
	}
	if _, err := os.Stat(filepath.Join(e.root, "file.bin")); !os.IsNotExist(err) {
		t.Fatal("bad file must not be moved into place")
	}
}

func TestNeverOverwrite(t *testing.T) {
	content := testserver.Content(64<<10, 7)
	srv := testserver.New(content, testserver.Options{})
	defer srv.Close()
	e := newEnv(t)
	os.WriteFile(filepath.Join(e.root, "file.bin"), []byte("mine"), 0o644)
	m := e.manager(t)
	defer m.Close()
	m.Start()
	job, _ := m.Add(AddRequest{URL: srv.FileURL()})
	v := waitDone(t, m, job.ID, 10*time.Second)
	checkFile(t, v, content)
	if filepath.Base(v.FinalPath) != "file (1).bin" {
		t.Fatalf("final name %s", v.FinalPath)
	}
	if b, _ := os.ReadFile(filepath.Join(e.root, "file.bin")); string(b) != "mine" {
		t.Fatal("existing file was overwritten")
	}
}

func TestContentDispositionNameIsSanitized(t *testing.T) {
	content := testserver.Content(1024, 7)
	srv := testserver.New(content, testserver.Options{Disposition: `attachment; filename="..\\..\\evil:stream.exe"`})
	defer srv.Close()
	e := newEnv(t)
	m := e.manager(t)
	defer m.Close()
	m.Start()
	job, _ := m.Add(AddRequest{URL: srv.FileURL()})
	v := waitDone(t, m, job.ID, 10*time.Second)
	checkFile(t, v, content)
	if filepath.Dir(v.FinalPath) != e.root || strings.Contains(filepath.Base(v.FinalPath), ":") {
		t.Fatalf("unsafe final path %s", v.FinalPath)
	}
}

func TestDuplicateURL(t *testing.T) {
	srv := testserver.New(testserver.Content(1024, 7), testserver.Options{StallAfter: 10})
	defer srv.Close()
	e := newEnv(t)
	m := e.manager(t)
	defer m.Close()
	if _, err := m.Add(AddRequest{URL: srv.FileURL()}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Add(AddRequest{URL: srv.FileURL()}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expected duplicate error, got %v", err)
	}
	if _, err := m.Add(AddRequest{URL: srv.FileURL(), AllowDuplicate: true}); err != nil {
		t.Fatal(err)
	}
}

func TestDiskFullPausesAndResumes(t *testing.T) {
	content := testserver.Content(256<<10, 7)
	srv := testserver.New(content, testserver.Options{})
	defer srv.Close()
	e := newEnv(t)
	free := uint64(0)
	e.opts.Disk = &policy.DiskGuard{MinFree: 1 << 20, Stat: func(string) (policy.DiskInfo, error) {
		return policy.DiskInfo{Free: free}, nil
	}}
	m := e.manager(t)
	defer m.Close()
	m.Start()
	job, _ := m.Add(AddRequest{URL: srv.FileURL(), ExpectedSize: int64(len(content))})
	deadline := time.Now().Add(5 * time.Second)
	for {
		v, _ := m.Get(job.ID)
		if v.State == state.StatePausedDisk {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("never paused for disk; state %s", v.State)
		}
		time.Sleep(5 * time.Millisecond)
	}
	free = 1 << 30
	v := waitDone(t, m, job.ID, 10*time.Second)
	checkFile(t, v, content)
}

func TestFAT32Refused(t *testing.T) {
	e := newEnv(t)
	e.opts.Disk = &policy.DiskGuard{Stat: func(string) (policy.DiskInfo, error) {
		return policy.DiskInfo{Free: 1 << 40, FSType: "FAT32"}, nil
	}}
	m := e.manager(t)
	defer m.Close()
	_, err := m.Add(AddRequest{URL: "http://127.0.0.1:1/x.bin", ExpectedSize: 5 << 30})
	if err == nil || !strings.Contains(err.Error(), "FAT32") {
		t.Fatalf("expected FAT32 refusal, got %v", err)
	}
}

func TestSaveFolderVanishes(t *testing.T) {
	content := testserver.Content(64<<10, 7)
	srv := testserver.New(content, testserver.Options{})
	defer srv.Close()
	e := newEnv(t)
	sub := filepath.Join(e.root, "sub")
	os.Mkdir(sub, 0o755)
	m := e.manager(t)
	job, err := m.Add(AddRequest{URL: srv.FileURL(), Dir: "sub"})
	if err != nil {
		t.Fatal(err)
	}
	os.RemoveAll(sub)
	m.Start()
	defer m.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		v, _ := m.Get(job.ID)
		if v.State == state.StatePausedNoDir {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("state %s", v.State)
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := os.Stat(sub); !os.IsNotExist(err) {
		t.Fatal("folder must not be recreated silently")
	}
	os.Mkdir(sub, 0o755)
	v := waitDone(t, m, job.ID, 10*time.Second)
	checkFile(t, v, content)
}

func TestPauseResumeCancel(t *testing.T) {
	content := testserver.Content(1<<20, 7)
	srv := testserver.New(content, testserver.Options{})
	defer srv.Close()
	e := newEnv(t)
	e.opts.SpeedLimit = 512 << 10
	m := e.manager(t)
	defer m.Close()
	m.Start()
	job, _ := m.Add(AddRequest{URL: srv.FileURL(), SHA256: testserver.SHA256(content)})
	time.Sleep(300 * time.Millisecond)
	if err := m.Pause(job.ID); err != nil {
		t.Fatal(err)
	}
	v := waitDone(t, m, job.ID, 5*time.Second)
	if v.State != state.StatePaused {
		t.Fatalf("state %s", v.State)
	}
	m.SetLimit(0)
	if err := m.Resume(job.ID); err != nil {
		t.Fatal(err)
	}
	v = waitDone(t, m, job.ID, 10*time.Second)
	checkFile(t, v, content)

	job2, _ := m.Add(AddRequest{URL: srv.FileURL(), AllowDuplicate: true})
	m.SetLimit(64 << 10)
	time.Sleep(200 * time.Millisecond)
	m.Cancel(job2.ID)
	v = waitDone(t, m, job2.ID, 5*time.Second)
	if v.State != state.StateCancelled {
		t.Fatalf("state %s", v.State)
	}
	if _, err := os.Stat(v.PartPath); !os.IsNotExist(err) {
		t.Fatal("part file should be deleted on cancel")
	}
}

// TestCrashRecovery simulates hard kills: the manager is stopped at random
// points (like a power cut), garbage is appended to the part file past the
// last checkpoint (unsynced data), and a new manager resumes from the
// journal. The final SHA-256 must match.
func TestCrashRecovery(t *testing.T) {
	content := testserver.Content(2<<20, 7)
	srv := testserver.New(content, testserver.Options{})
	defer srv.Close()
	e := newEnv(t)
	e.opts.SpeedLimit = 4 << 20
	rng := rand.New(rand.NewSource(1))
	m := e.manager(t)
	m.Start()
	job, err := m.Add(AddRequest{URL: srv.FileURL(), SHA256: testserver.SHA256(content)})
	if err != nil {
		t.Fatal(err)
	}
	for kill := 0; kill < 20; kill++ {
		time.Sleep(time.Duration(rng.Intn(40)) * time.Millisecond)
		m.Close()
		// Simulate data that reached the file but not the journal.
		if j, err := e.journal.Load(job.ID); err == nil && j.PartPath != "" && j.State != state.StateDone {
			if f, err := os.OpenFile(j.PartPath, os.O_WRONLY|os.O_APPEND, 0); err == nil {
				f.Write(bytes.Repeat([]byte{0xEE}, rng.Intn(100000)))
				f.Close()
			}
		}
		m = e.manager(t)
		m.Start()
	}
	defer m.Close()
	v := waitDone(t, m, job.ID, 30*time.Second)
	checkFile(t, v, content)
}

func TestProbe(t *testing.T) {
	content := testserver.Content(100000, 7)
	srv := testserver.New(content, testserver.Options{Disposition: `attachment; filename="file.bin"`})
	defer srv.Close()
	e := newEnv(t)
	c := e.opts.URLPolicy.NewClient(policy.ClientOptions{})
	r, err := Probe(context.Background(), c, e.opts.URLPolicy, srv.URL+"/redirect", "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Resumable != ResumableYes || r.Size != int64(len(content)) || r.Redirects != 1 || r.Filename != "file.bin" {
		t.Fatalf("%+v", r)
	}

	cases := []struct {
		o    testserver.Options
		want string
	}{
		{testserver.Options{IgnoreRange: true}, ResumableNoRanges},
		{testserver.Options{NoLength: true}, ResumableNoLength},
		{testserver.Options{NoValidators: true}, ResumableRiskyNoTag},
		{testserver.Options{Multipart: true}, ResumableNoRanges},
		{testserver.Options{HEADForbidden: true}, ResumableYes},
	}
	for _, c2 := range cases {
		s := testserver.New(content, c2.o)
		r, err := Probe(context.Background(), c, e.opts.URLPolicy, s.FileURL(), "")
		s.Close()
		if err != nil {
			t.Fatal(err)
		}
		if r.Resumable != c2.want {
			t.Errorf("%+v: resumable = %q, want %q", c2.o, r.Resumable, c2.want)
		}
	}
}

func TestProbeBlocksPrivate(t *testing.T) {
	up := &policy.URLPolicy{}
	c := up.NewClient(policy.ClientOptions{})
	srv := testserver.New([]byte("x"), testserver.Options{})
	defer srv.Close()
	if _, err := Probe(context.Background(), c, up, srv.FileURL(), ""); !errors.Is(err, policy.ErrBlocked) {
		t.Fatalf("expected policy block, got %v", err)
	}
}
