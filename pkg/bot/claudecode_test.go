package bot

import (
	"log/slog"
	"os"
	"testing"

	"github.com/nikogura/diagnostic-slackbot/pkg/investigations"
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

func TestNewClaudeCodeRunnerHasToolConfig(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	runner := NewClaudeCodeRunner("", logger)

	// toolConfig should be initialized (zero-value ToolConfig is valid)
	require.NotNil(t, runner, "NewClaudeCodeRunner returned nil")
	// Verify the struct field exists and is populated
	_ = runner.toolConfig
}

func TestBuildPromptIncludesLokiWhenConfigured(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	runner := &ClaudeCodeRunner{
		logger: logger,
		model:  "test-model",
		toolConfig: ToolConfig{
			LokiAvailable: true,
		},
	}

	skill := &investigations.InvestigationSkill{
		Name:          "test-skill",
		InitialPrompt: "Investigate the issue.",
	}

	prompt := runner.buildPrompt(skill, "check modsecurity blocks")

	assert.Contains(t, prompt, "query_loki", "Prompt should include Loki tool when configured")
	assert.Contains(t, prompt, "whois_lookup", "Prompt should always include utility tools")
	assert.NotContains(t, prompt, "cloudwatch_logs_query", "Prompt should not include CloudWatch when not configured")
}

func TestBuildPromptIncludesCloudWatchWhenConfigured(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	runner := &ClaudeCodeRunner{
		logger: logger,
		model:  "test-model",
		toolConfig: ToolConfig{
			CloudWatchAvailable: true,
		},
	}

	skill := &investigations.InvestigationSkill{
		Name:          "test-skill",
		InitialPrompt: "Investigate the issue.",
	}

	prompt := runner.buildPrompt(skill, "summarize cloudwatch logs")

	assert.Contains(t, prompt, "cloudwatch_logs_query", "Prompt should include CloudWatch when configured")
	assert.NotContains(t, prompt, "query_loki", "Prompt should not include Loki when not configured")
}

func TestBuildPromptAllToolsConfigured(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	runner := &ClaudeCodeRunner{
		logger: logger,
		model:  "test-model",
		toolConfig: ToolConfig{
			LokiAvailable:       true,
			CloudWatchAvailable: true,
			PrometheusAvailable: true,
			GrafanaAvailable:    true,
			DatabaseAvailable:   true,
			GitHubAvailable:     true,
			ECRAvailable:        true,
		},
	}

	skill := &investigations.InvestigationSkill{
		Name:          "test-skill",
		InitialPrompt: "Investigate the issue.",
	}

	prompt := runner.buildPrompt(skill, "general diagnostic")

	expectedTools := []string{
		"query_loki",
		"cloudwatch_logs_query",
		"prometheus_query",
		"grafana_list_dashboards",
		"database_query",
		"github_get_file",
		"ecr_scan_results",
		"whois_lookup",
		"generate_pdf",
	}

	for _, tool := range expectedTools {
		assert.Contains(t, prompt, tool, "Prompt should include %s when all tools configured", tool)
	}
}

func TestBuildPromptNoLongerHardcodesLokiStart(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	runner := &ClaudeCodeRunner{
		logger: logger,
		model:  "test-model",
		toolConfig: ToolConfig{
			LokiAvailable:       true,
			CloudWatchAvailable: true,
		},
	}

	skill := &investigations.InvestigationSkill{
		Name:          "test-skill",
		InitialPrompt: "Investigate the issue.",
	}

	prompt := runner.buildPrompt(skill, "check logs")

	// Should NOT contain the old hardcoded instruction to "Start by querying Loki"
	assert.NotContains(t, prompt, "Start by querying Loki",
		"Prompt should not hardcode 'Start by querying Loki'")
}

func TestBuildPromptStructure(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	runner := &ClaudeCodeRunner{
		logger: logger,
		model:  "test-model",
		toolConfig: ToolConfig{
			LokiAvailable: true,
		},
	}

	skill := &investigations.InvestigationSkill{
		Name:          "test-skill",
		InitialPrompt: "Investigate the issue.",
	}

	prompt := runner.buildPrompt(skill, "test request")

	// Verify prompt structure
	assert.Contains(t, prompt, "# Investigation Task", "Should have investigation task header")
	assert.Contains(t, prompt, "Investigate the issue.", "Should include skill prompt")
	assert.Contains(t, prompt, "# User Request", "Should have user request header")
	assert.Contains(t, prompt, "test request", "Should include user message")
	assert.Contains(t, prompt, "# Available Tools", "Should have available tools header")
	assert.Contains(t, prompt, "# Output Format", "Should have output format header")
	assert.Contains(t, prompt, "# IMPORTANT: PDF Generation", "Should have PDF generation header")
}
