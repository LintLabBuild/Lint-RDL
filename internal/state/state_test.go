package state

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestJournal(t *testing.T) {
	j, err := OpenJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a := &Job{ID: "aaaa1111", URL: "https://x/a", CreatedAt: time.Now(), State: StateQueued, ExpectedSize: -1}
	b := &Job{ID: "bbbb2222", URL: "https://x/b", CreatedAt: time.Now().Add(time.Second), State: StateDone}
	j.Save(b)
	j.Save(a)
	os.WriteFile(filepath.Join(j.Dir(), "cccc3333.json"), []byte("{torn"), 0o600)
	all, errs := j.All()
	if len(all) != 2 || all[0].ID != "aaaa1111" || len(errs) != 1 {
		t.Fatalf("%v %v", all, errs)
	}
	if err := j.Save(&Job{ID: "../evil"}); err == nil {
		t.Fatal("bad id accepted")
	}
	if _, err := j.Load("../../etc/passwd"); err == nil {
		t.Fatal("path traversal in Load")
	}
	j.Delete("aaaa1111")
	all, _ = j.All()
	if len(all) != 1 {
		t.Fatal(len(all))
	}
	if StateQueued.Terminal() || !StateDone.Terminal() {
		t.Fatal("terminal")
	}
}

func TestAuditRotation(t *testing.T) {
	a, _ := OpenAudit(filepath.Join(t.TempDir(), "audit.log"), 300)
	for i := 0; i < 20; i++ {
		if err := a.Log(AuditEntry{Identity: "cli:me", Command: "add", Result: "ok"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(a.Path() + ".1"); err != nil {
		t.Fatal("no rotation")
	}
	es, _ := a.Tail(1)
	if len(es) != 1 || es[0].Identity != "cli:me" {
		t.Fatal(es)
	}
}

func TestLock(t *testing.T) {
	d := t.TempDir()
	l, err := AcquireLock(d)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireLock(d); err == nil {
		t.Fatal("second lock acquired")
	}
	l.Release()
	l2, err := AcquireLock(d)
	if err != nil {
		t.Fatal(err)
	}
	l2.Release()
}
