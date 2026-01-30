package claude

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClientWithModel(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	tests := []struct {
		name          string
		apiKey        string
		model         string
		expectedModel string
	}{
		{
			name:          "custom model specified",
			apiKey:        "test-key",
			model:         "claude-opus-4-20250514",
			expectedModel: "claude-opus-4-20250514",
		},
		{
			name:          "empty model uses default",
			apiKey:        "test-key",
			model:         "",
			expectedModel: ModelSonnet45,
		},
		{
			name:          "default model constant",
			apiKey:        "test-key",
			model:         ModelSonnet45,
			expectedModel: ModelSonnet45,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := NewClient(tt.apiKey, tt.model, logger)

			require.NotNil(t, client, "NewClient returned nil")
			assert.Equal(t, tt.expectedModel, client.model, "NewClient() model mismatch")
			require.NotNil(t, client.logger, "NewClient() logger is nil")
			require.NotNil(t, client.client, "NewClient() anthropic client is nil")
		})
	}
}

func TestNewClientDefaultModel(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	client := NewClient("test-key", "", logger)

	if client.model != ModelSonnet45 {
		t.Errorf("NewClient with empty model should default to %q, got %q", ModelSonnet45, client.model)
	}
}

func TestModelConstant(t *testing.T) {
	t.Parallel()

	expectedModel := "claude-sonnet-4-5-20250929"
	if ModelSonnet45 != expectedModel {
		t.Errorf("ModelSonnet45 constant = %q, want %q", ModelSonnet45, expectedModel)
	}
}
