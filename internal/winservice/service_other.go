//go:build !windows

// Package winservice — stub voor non-Windows platforms. Service install is
// Windows-only; op Linux/macOS runnen we de agent in foreground mode of via
// systemd/launchd (niet in scope).
package winservice

import (
	"context"
	"errors"
)

var errWindowsOnly = errors.New("service commands zijn alleen op Windows ondersteund")

func Install() error   { return errWindowsOnly }
func Uninstall() error { return errWindowsOnly }

type Runner func(ctx context.Context) error

func Run(_ Runner) error { return errWindowsOnly }
