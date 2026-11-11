package power

import "testing"

func TestAwakeRefCount(t *testing.T) {
	var a Awake
	a.Acquire()
	a.Acquire()
	a.Release()
	if a.count != 1 || a.rel == nil {
		t.Fatal("released too early")
	}
	a.Release()
	a.Release() // extra release is harmless
	if a.count != 0 || a.rel != nil {
		t.Fatal("not released")
	}
}
