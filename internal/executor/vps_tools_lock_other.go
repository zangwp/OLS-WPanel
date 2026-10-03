//go:build !linux

package executor

func lockSimpleVPSTools() (func(), error) { return func() {}, nil }
