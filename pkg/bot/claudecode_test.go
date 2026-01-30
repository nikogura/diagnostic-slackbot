package bot

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClaudeCodeRunnerWithModel(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	tests := []struct {
		name          string
		model         string
		expectedModel string
	}{
		{
			name:          "custom model specified",
			model:         "claude-opus-4-20250514",
			expectedModel: "claude-opus-4-20250514",
		},
		{
			name:          "empty model uses default",
			model:         "",
			expectedModel: "claude-sonnet-4-5-20250929",
		},
		{
			name:          "sonnet alias",
			model:         "sonnet",
			expectedModel: "sonnet",
		},
		{
			name:          "opus alias",
			model:         "opus",
			expectedModel: "opus",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			runner := NewClaudeCodeRunner(tt.model, logger)

			require.NotNil(t, runner, "NewClaudeCodeRunner returned nil")
			assert.Equal(t, tt.expectedModel, runner.model, "NewClaudeCodeRunner() model mismatch")
			require.NotNil(t, runner.logger, "NewClaudeCodeRunner() logger is nil")
		})
	}
}

func TestNewClaudeCodeRunnerDefaultModel(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	runner := NewClaudeCodeRunner("", logger)

	expectedDefault := "claude-sonnet-4-5-20250929"
	if runner.model != expectedDefault {
		t.Errorf("NewClaudeCodeRunner with empty model should default to %q, got %q", expectedDefault, runner.model)
	}
}
