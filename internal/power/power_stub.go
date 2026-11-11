//go:build !windows && !linux && !darwin

package power

func keepAwake() func() { return func() {} }
