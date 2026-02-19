package bot

import (
	"sync"
	"time"
)

// InvestigationTracker prevents duplicate investigations from running concurrently.
// It tracks active investigations by a composite key (channel:userID) and rejects
// new requests when one is already in progress for the same key.
type InvestigationTracker struct {
	mu     sync.Mutex
	active map[string]time.Time
}

// NewInvestigationTracker creates a new investigation tracker.
func NewInvestigationTracker() (result *InvestigationTracker) {
	result = &InvestigationTracker{
		active: make(map[string]time.Time),
	}

	return result
}

// TryStart attempts to start an investigation for the given key.
// Returns true if the investigation was started (no existing one for this key).
// Returns false if an investigation is already active for this key.
func (t *InvestigationTracker) TryStart(key string) (started bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	_, exists := t.active[key]
	if exists {
		return started
	}

	t.active[key] = time.Now()
	started = true

	return started
}

// Done marks an investigation as complete for the given key.
func (t *InvestigationTracker) Done(key string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.active, key)
}

// IsActive checks if an investigation is active for the given key.
func (t *InvestigationTracker) IsActive(key string) (active bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	_, active = t.active[key]

	return active
}

// Count returns the number of active investigations.
func (t *InvestigationTracker) Count() (result int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	result = len(t.active)

	return result
}

// InvestigationKey builds a tracker key from channel and user ID.
func InvestigationKey(channel string, userID string) (result string) {
	result = channel + ":" + userID

	return result
}
