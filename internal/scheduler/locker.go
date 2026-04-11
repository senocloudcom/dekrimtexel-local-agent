package scheduler

import "sync"

// SwitchLocker tracks which switches are currently being scanned, so that
// two concurrent scan triggers (manual GUI + periodic background, or two
// overlapping manual scans) cannot scan the same switch at the same time.
//
// The lock is per-switch (not global): scans of different switches run
// in parallel without contention.
//
// Internally backed by sync.Map for lock-free reads when there is no
// contention.
type SwitchLocker struct {
	locks sync.Map // map[int]struct{} — present means "locked"
}

// TryLock attempts to mark the switch as being scanned.
// Returns true if the lock was acquired (caller may proceed),
// false if the switch is already being scanned by someone else.
func (l *SwitchLocker) TryLock(switchID int) bool {
	_, alreadyLocked := l.locks.LoadOrStore(switchID, struct{}{})
	return !alreadyLocked
}

// Unlock releases the lock so the switch can be scanned again.
// Always defer this immediately after a successful TryLock.
func (l *SwitchLocker) Unlock(switchID int) {
	l.locks.Delete(switchID)
}

// IsLocked is a helper for tests / introspection. Not used in the hot path.
func (l *SwitchLocker) IsLocked(switchID int) bool {
	_, ok := l.locks.Load(switchID)
	return ok
}
