package bot

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInvestigationTrackerTryStart(t *testing.T) {
	t.Parallel()

	tracker := NewInvestigationTracker()

	// First start should succeed
	started := tracker.TryStart("C123:U456")
	assert.True(t, started, "First TryStart should return true")

	// Second start for same key should fail
	started = tracker.TryStart("C123:U456")
	assert.False(t, started, "Second TryStart for same key should return false")

	// Different key should succeed
	started = tracker.TryStart("C123:U789")
	assert.True(t, started, "TryStart for different key should return true")
}

func TestInvestigationTrackerDone(t *testing.T) {
	t.Parallel()

	tracker := NewInvestigationTracker()

	// Start and complete
	started := tracker.TryStart("C123:U456")
	require.True(t, started, "TryStart should return true")

	tracker.Done("C123:U456")

	// Should be able to start again after Done
	started = tracker.TryStart("C123:U456")
	assert.True(t, started, "TryStart after Done should return true")
}

func TestInvestigationTrackerDoneNonExistent(t *testing.T) {
	t.Parallel()

	tracker := NewInvestigationTracker()

	// Done on non-existent key should not panic
	tracker.Done("nonexistent")

	assert.Equal(t, 0, tracker.Count(), "Count should be 0 after Done on non-existent key")
}

func TestInvestigationTrackerIsActive(t *testing.T) {
	t.Parallel()

	tracker := NewInvestigationTracker()

	// Not active initially
	active := tracker.IsActive("C123:U456")
	assert.False(t, active, "IsActive should return false for untracked key")

	// Active after TryStart
	tracker.TryStart("C123:U456")

	active = tracker.IsActive("C123:U456")
	assert.True(t, active, "IsActive should return true after TryStart")

	// Not active after Done
	tracker.Done("C123:U456")

	active = tracker.IsActive("C123:U456")
	assert.False(t, active, "IsActive should return false after Done")
}

func TestInvestigationTrackerCount(t *testing.T) {
	t.Parallel()

	tracker := NewInvestigationTracker()

	assert.Equal(t, 0, tracker.Count(), "Initial count should be 0")

	tracker.TryStart("C1:U1")
	assert.Equal(t, 1, tracker.Count(), "Count should be 1 after one TryStart")

	tracker.TryStart("C1:U2")
	assert.Equal(t, 2, tracker.Count(), "Count should be 2 after two TryStarts")

	// Duplicate should not increase count
	tracker.TryStart("C1:U1")
	assert.Equal(t, 2, tracker.Count(), "Count should still be 2 after duplicate TryStart")

	tracker.Done("C1:U1")
	assert.Equal(t, 1, tracker.Count(), "Count should be 1 after one Done")
}

func TestInvestigationKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		channel  string
		userID   string
		expected string
	}{
		{
			name:     "basic key",
			channel:  "C12345",
			userID:   "U67890",
			expected: "C12345:U67890",
		},
		{
			name:     "empty channel",
			channel:  "",
			userID:   "U67890",
			expected: ":U67890",
		},
		{
			name:     "empty user",
			channel:  "C12345",
			userID:   "",
			expected: "C12345:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := InvestigationKey(tt.channel, tt.userID)
			assert.Equal(t, tt.expected, result, "InvestigationKey mismatch")
		})
	}
}

func TestInvestigationTrackerConcurrentAccess(t *testing.T) {
	t.Parallel()

	tracker := NewInvestigationTracker()

	var wg sync.WaitGroup

	// Simulate concurrent TryStart for the same key — only one should win
	successes := make(chan bool, 20)

	for range 20 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			started := tracker.TryStart("C1:U1")
			successes <- started
		}()
	}

	wg.Wait()
	close(successes)

	successCount := 0

	for started := range successes {
		if started {
			successCount++
		}
	}

	assert.Equal(t, 1, successCount, "Only one concurrent TryStart should succeed")
	assert.Equal(t, 1, tracker.Count(), "Count should be 1 after concurrent TryStarts")
}

func TestInvestigationTrackerConcurrentDifferentKeys(t *testing.T) {
	t.Parallel()

	tracker := NewInvestigationTracker()

	var wg sync.WaitGroup

	// Simulate concurrent TryStart for different keys — all should succeed
	for i := range 10 {
		wg.Add(1)

		go func(id int) {
			defer wg.Done()

			key := InvestigationKey("C1", string(rune('A'+id)))
			started := tracker.TryStart(key)
			assert.True(t, started, "TryStart for unique key should succeed")
		}(i)
	}

	wg.Wait()
	assert.Equal(t, 10, tracker.Count(), "All 10 unique keys should be active")
}

func TestInvestigationTrackerStartDoneStart(t *testing.T) {
	t.Parallel()

	tracker := NewInvestigationTracker()

	// Simulate the full lifecycle multiple times
	for range 5 {
		started := tracker.TryStart("C1:U1")
		require.True(t, started, "TryStart should succeed at start of cycle")

		// Verify active
		assert.True(t, tracker.IsActive("C1:U1"), "Should be active during cycle")

		tracker.Done("C1:U1")

		// Verify inactive
		assert.False(t, tracker.IsActive("C1:U1"), "Should be inactive after Done")
	}
}
