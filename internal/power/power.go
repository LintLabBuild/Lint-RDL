// Package power keeps the PC awake while downloads run. Sleep, hibernate
// and shutdown actions arrive with the daemon (phase 2).
package power

import "sync"

// Awake holds a keep-awake request while count > 0.
type Awake struct {
	mu    sync.Mutex
	count int
	rel   func()
}

// Acquire increments the hold count; the first holder starts keep-awake.
func (a *Awake) Acquire() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.count++
	if a.count == 1 {
		a.rel = keepAwake()
	}
}

// Release decrements the hold count; the last holder lets the PC sleep.
func (a *Awake) Release() {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.count == 0 {
		return
	}
	a.count--
	if a.count == 0 && a.rel != nil {
		a.rel()
		a.rel = nil
	}
}
