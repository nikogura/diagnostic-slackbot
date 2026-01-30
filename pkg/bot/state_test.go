package bot

import (
	"testing"
	"time"

	"github.com/nikogura/diagnostic-slackbot/pkg/investigations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConversationStoreCreateAndGet(t *testing.T) {
	t.Parallel()

	store := NewConversationStore(24 * time.Hour)

	// Create test conversation
	conv := store.Create("1234567890.123456", "C12345", "U12345", investigations.InvestigationTypeModSecurity)

	require.NotNil(t, conv, "Create() returned nil")

	// Verify fields
	assert.Equal(t, "1234567890.123456", conv.SlackThreadTS, "SlackThreadTS mismatch")
	assert.Equal(t, "U12345", conv.UserID, "UserID mismatch")
	assert.Equal(t, ConversationStateActive, conv.State, "State mismatch")

	// Retrieve by thread TS
	retrieved, exists := store.Get("1234567890.123456")
	require.True(t, exists, "Get() returned exists=false, expected true")
	require.NotNil(t, retrieved, "Get() returned nil")

	assert.Equal(t, conv.ID, retrieved.ID, "Get() ID mismatch")
}

func TestConversationStoreGetNonExistent(t *testing.T) {
	t.Parallel()

	store := NewConversationStore(24 * time.Hour)

	// Try to get non-existent conversation
	_, exists := store.Get("nonexistent")
	if exists {
		t.Error("Get() for non-existent thread returned exists=true, want false")
	}
}

func TestConversationStoreCount(t *testing.T) {
	t.Parallel()

	store := NewConversationStore(24 * time.Hour)

	// Initial count should be 0
	if store.Count() != 0 {
		t.Errorf("Initial count = %d, want 0", store.Count())
	}

	// Create conversations
	for i := range 5 {
		threadTS := string(rune('0' + i))
		store.Create(threadTS, "C12345", "U12345", investigations.InvestigationTypeModSecurity)
	}

	// Count should be 5
	if store.Count() != 5 {
		t.Errorf("Count after creating 5 = %d, want 5", store.Count())
	}
}

func TestConversationStoreList(t *testing.T) {
	t.Parallel()

	store := NewConversationStore(24 * time.Hour)

	// Create multiple conversations
	store.Create("thread1", "C1", "U1", investigations.InvestigationTypeModSecurity)
	store.Create("thread2", "C1", "U2", investigations.InvestigationTypeAtlas)
	store.Create("thread3", "C1", "U3", investigations.InvestigationTypePodCrash)

	// List all
	all := store.List()
	if len(all) != 3 {
		t.Errorf("List() returned %d conversations, want 3", len(all))
	}

	// Verify all thread TSs present
	ids := make(map[string]bool)
	for _, conv := range all {
		ids[conv.SlackThreadTS] = true
	}

	expected := []string{"thread1", "thread2", "thread3"}
	for _, expectedTS := range expected {
		if !ids[expectedTS] {
			t.Errorf("List() missing conversation thread TS %s", expectedTS)
		}
	}
}

func TestConversationStoreCleanupExpired(t *testing.T) {
	t.Parallel()

	store := NewConversationStore(24 * time.Hour)

	// Create old conversation
	oldConv := store.Create("thread-old", "C1", "U1", investigations.InvestigationTypeModSecurity)
	oldConv.LastActivity = time.Now().Add(-25 * time.Hour)

	// Create new conversation
	store.Create("thread-new", "C1", "U2", investigations.InvestigationTypeModSecurity)

	// Cleanup expired conversations
	expiredCount := store.CleanupExpired()

	if expiredCount != 1 {
		t.Errorf("CleanupExpired() expired %d conversations, want 1", expiredCount)
	}

	// Old conversation should be removed
	_, exists := store.Get("thread-old")
	if exists {
		t.Error("Old conversation not expired")
	}

	// New conversation should still exist
	_, exists = store.Get("thread-new")
	if !exists {
		t.Error("New conversation was incorrectly expired")
	}
}

func TestConversationStoreConcurrentAccess(t *testing.T) {
	t.Parallel()

	store := NewConversationStore(24 * time.Hour)

	// Simulate concurrent creates
	done := make(chan bool)

	for i := range 10 {
		go func(id int) {
			threadTS := string(rune('0' + id))
			store.Create(threadTS, "C1", "U1", investigations.InvestigationTypeModSecurity)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for range 10 {
		<-done
	}

	// Should have all 10 conversations
	if store.Count() != 10 {
		t.Errorf("Concurrent creates resulted in %d conversations, want 10", store.Count())
	}
}

func TestConversationStateString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		state ConversationState
		want  string
	}{
		{
			name:  "active",
			state: ConversationStateActive,
			want:  "active",
		},
		{
			name:  "resolved",
			state: ConversationStateResolved,
			want:  "resolved",
		},
		{
			name:  "abandoned",
			state: ConversationStateAbandoned,
			want:  "abandoned",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := string(tt.state)
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}
