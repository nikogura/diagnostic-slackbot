package mcp

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/nikogura/diagnostic-slackbot/pkg/k8s"
	"github.com/stretchr/testify/require"
)

func TestGetGitHubTools(t *testing.T) {
	t.Parallel()

	tools := getGitHubTools()

	// Should have 3 GitHub tools
	expectedCount := 3
	if len(tools) != expectedCount {
		t.Fatalf("getGitHubTools() returned %d tools, want %d", len(tools), expectedCount)
	}

	// Check tool names
	expectedTools := map[string]bool{
		"github_get_file":       false,
		"github_list_directory": false,
		"github_search_code":    false,
	}

	for _, tool := range tools {
		if _, exists := expectedTools[tool.Name]; exists {
			expectedTools[tool.Name] = true
		}
	}

	for name, found := range expectedTools {
		if !found {
			t.Errorf("Expected tool %s not found in getGitHubTools()", name)
		}
	}
}

func TestGetLokiTools(t *testing.T) {
	t.Parallel()

	tools := getLokiTools()

	// Should have 1 Loki tool
	if len(tools) != 1 {
		t.Fatalf("getLokiTools() returned %d tools, want 1", len(tools))
	}

	if tools[0].Name != "query_loki" {
		t.Errorf("getLokiTools() tool name = %s, want query_loki", tools[0].Name)
	}
}

func TestGetUtilityTools(t *testing.T) {
	t.Parallel()

	tools := getUtilityTools()

	// Should have 2 utility tools
	expectedCount := 2
	if len(tools) != expectedCount {
		t.Fatalf("getUtilityTools() returned %d tools, want %d", len(tools), expectedCount)
	}

	expectedTools := map[string]bool{
		"whois_lookup": false,
		"generate_pdf": false,
	}

	for _, tool := range tools {
		if _, exists := expectedTools[tool.Name]; exists {
			expectedTools[tool.Name] = true
		}
	}

	for name, found := range expectedTools {
		if !found {
			t.Errorf("Expected tool %s not found in getUtilityTools()", name)
		}
	}
}

func TestGetToolDefinitionsMinimalServer(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	// Clear env vars that affect tool registration
	t.Setenv("CLOUDWATCH_ASSUME_ROLE", "")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")

	// Server with only Loki client, no other services
	lokiClient := k8s.NewLokiClient("http://dummy:3100", logger)
	server := NewServer(lokiClient, "", logger)

	tools := server.getToolDefinitions()

	// Should have Loki (1) + Utility (2) = 3 tools minimum
	toolMap := make(map[string]bool)
	for _, tool := range tools {
		toolMap[tool.Name] = true
	}

	// Loki tools should be present (lokiClient is non-nil)
	require.True(t, toolMap["query_loki"], "Loki tool should be present when lokiClient is set")

	// Utility tools should always be present
	require.True(t, toolMap["whois_lookup"], "whois_lookup should always be present")
	require.True(t, toolMap["generate_pdf"], "generate_pdf should always be present")

	// GitHub tools should NOT be present (no token)
	require.False(t, toolMap["github_get_file"], "GitHub tools should not be present without token")

	// Database tools should NOT be present (no DATABASE_URL)
	require.False(t, toolMap["database_query"], "Database tools should not be present without config")
}

func TestGetToolDefinitionsWithGitHub(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	// Clear env vars
	t.Setenv("CLOUDWATCH_ASSUME_ROLE", "")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")

	lokiClient := k8s.NewLokiClient("http://dummy:3100", logger)
	server := NewServer(lokiClient, "test-token", logger)

	tools := server.getToolDefinitions()

	toolMap := make(map[string]bool)
	for _, tool := range tools {
		toolMap[tool.Name] = true
	}

	// GitHub tools should be present
	require.True(t, toolMap["github_get_file"], "GitHub tools should be present with token")
	require.True(t, toolMap["github_list_directory"], "GitHub list directory should be present")
	require.True(t, toolMap["github_search_code"], "GitHub search should be present")
}

func TestGetToolDefinitionsWithCloudWatch(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	t.Setenv("CLOUDWATCH_ASSUME_ROLE", "arn:aws:iam::123456789012:role/test")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")

	lokiClient := k8s.NewLokiClient("http://dummy:3100", logger)
	server := NewServer(lokiClient, "", logger)

	tools := server.getToolDefinitions()

	toolMap := make(map[string]bool)
	for _, tool := range tools {
		toolMap[tool.Name] = true
	}

	require.True(t, toolMap["cloudwatch_logs_query"], "CloudWatch query should be present with CLOUDWATCH_ASSUME_ROLE")
	require.True(t, toolMap["cloudwatch_logs_list_groups"], "CloudWatch list groups should be present")
	require.True(t, toolMap["cloudwatch_logs_get_events"], "CloudWatch get events should be present")
}

func TestGetToolDefinitionsWithoutCloudWatch(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	t.Setenv("CLOUDWATCH_ASSUME_ROLE", "")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")

	lokiClient := k8s.NewLokiClient("http://dummy:3100", logger)
	server := NewServer(lokiClient, "", logger)

	tools := server.getToolDefinitions()

	toolMap := make(map[string]bool)
	for _, tool := range tools {
		toolMap[tool.Name] = true
	}

	require.False(t, toolMap["cloudwatch_logs_query"], "CloudWatch should not be present without CLOUDWATCH_ASSUME_ROLE")
}

func TestGetToolDefinitionsWithECR(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("CLOUDWATCH_ASSUME_ROLE", "")

	lokiClient := k8s.NewLokiClient("http://dummy:3100", logger)
	server := NewServer(lokiClient, "", logger)

	tools := server.getToolDefinitions()

	toolMap := make(map[string]bool)
	for _, tool := range tools {
		toolMap[tool.Name] = true
	}

	require.True(t, toolMap["ecr_scan_results"], "ECR tool should be present with AWS_REGION")
}

func TestGetToolDefinitionsUtilityToolsAlwaysPresent(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	// Clear everything
	t.Setenv("CLOUDWATCH_ASSUME_ROLE", "")
	t.Setenv("AWS_REGION", "")
	t.Setenv("AWS_DEFAULT_REGION", "")

	// Server with nil lokiClient
	server := &Server{
		logger: logger,
	}

	tools := server.getToolDefinitions()

	toolMap := make(map[string]bool)
	for _, tool := range tools {
		toolMap[tool.Name] = true
	}

	require.True(t, toolMap["whois_lookup"], "whois_lookup should always be present")
	require.True(t, toolMap["generate_pdf"], "generate_pdf should always be present")
	require.Len(t, tools, 2, "Only utility tools should be present when nothing is configured")
}

func TestExecuteGitHubGetFileWithoutToken(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	lokiClient := k8s.NewLokiClient("http://dummy:3100", logger)
	server := NewServer(lokiClient, "", logger) // Empty GitHub token

	ctx := context.Background()
	args := map[string]interface{}{
		"owner": "your-org",
		"repo":  "test-repo",
		"path":  "README.md",
	}

	result, err := server.executeGitHubGetFile(ctx, args)

	// Should return error when GitHub client not configured
	if err == nil {
		t.Error("executeGitHubGetFile() without token should return error, got nil")
	}

	if !strings.Contains(err.Error(), "GitHub access not configured") {
		t.Errorf("executeGitHubGetFile() error = %v, want error containing 'GitHub access not configured'", err)
	}

	if result != "" {
		t.Errorf("executeGitHubGetFile() result = %q, want empty string", result)
	}
}

func TestExecuteGitHubListDirectoryWithoutToken(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	lokiClient := k8s.NewLokiClient("http://dummy:3100", logger)
	server := NewServer(lokiClient, "", logger)

	ctx := context.Background()
	args := map[string]interface{}{
		"owner": "your-org",
		"repo":  "test-repo",
		"path":  "db/migrations",
	}

	result, err := server.executeGitHubListDirectory(ctx, args)

	// Should return error when GitHub client not configured
	if err == nil {
		t.Error("executeGitHubListDirectory() without token should return error, got nil")
	}

	if !strings.Contains(err.Error(), "GitHub access not configured") {
		t.Errorf("executeGitHubListDirectory() error = %v, want error containing 'GitHub access not configured'", err)
	}

	if result != "" {
		t.Errorf("executeGitHubListDirectory() result = %q, want empty string", result)
	}
}

func TestExecuteGitHubSearchCodeWithoutToken(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	lokiClient := k8s.NewLokiClient("http://dummy:3100", logger)
	server := NewServer(lokiClient, "", logger)

	ctx := context.Background()
	args := map[string]interface{}{
		"query": "table users repo:your-org/test-repo",
	}

	result, err := server.executeGitHubSearchCode(ctx, args)

	// Should return error when GitHub client not configured
	if err == nil {
		t.Error("executeGitHubSearchCode() without token should return error, got nil")
	}

	if !strings.Contains(err.Error(), "GitHub access not configured") {
		t.Errorf("executeGitHubSearchCode() error = %v, want error containing 'GitHub access not configured'", err)
	}

	if result != "" {
		t.Errorf("executeGitHubSearchCode() result = %q, want empty string", result)
	}
}

func TestNewServerWithGitHubToken(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	lokiClient := k8s.NewLokiClient("http://dummy:3100", logger)
	server := NewServer(lokiClient, "test-token", logger)

	require.NotNil(t, server, "NewServer() returned nil")
	require.NotNil(t, server.githubClient, "NewServer() with GitHub token should initialize githubClient")
	require.NotNil(t, server.lokiClient, "NewServer() should have lokiClient")
}

func TestNewServerWithoutGitHubToken(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	lokiClient := k8s.NewLokiClient("http://dummy:3100", logger)
	server := NewServer(lokiClient, "", logger)

	require.NotNil(t, server, "NewServer() returned nil")
	require.Nil(t, server.githubClient, "NewServer() without GitHub token should not initialize githubClient")
	require.NotNil(t, server.lokiClient, "NewServer() should have lokiClient")
}

// verifyRequiredFields checks that all required fields exist in the properties map.
func verifyRequiredFields(t *testing.T, toolName string, propsMap map[string]interface{}, fields []string) {
	t.Helper()

	for _, field := range fields {
		if _, exists := propsMap[field]; !exists {
			t.Errorf("Tool %s missing required field %s in properties", toolName, field)
		}
	}
}

// validateToolSchema checks basic schema structure for a tool.
// Returns the properties map and a boolean indicating if validation passed.
func validateToolSchema(t *testing.T, tool MCPTool) (result map[string]interface{}, valid bool) {
	t.Helper()

	schema := tool.InputSchema

	// Check for required fields
	schemaType, hasType := schema["type"]
	if !hasType || schemaType != "object" {
		t.Errorf("Tool %s InputSchema missing type=object", tool.Name)
		valid = false
		return result, valid
	}

	properties, hasProperties := schema["properties"]
	if !hasProperties {
		t.Errorf("Tool %s InputSchema missing properties", tool.Name)
		valid = false
		return result, valid
	}

	propsMap, ok := properties.(map[string]interface{})
	if !ok {
		t.Errorf("Tool %s InputSchema properties is not a map", tool.Name)
		valid = false
		return result, valid
	}

	result = propsMap
	valid = true
	return result, valid
}

func TestGitHubToolInputSchemas(t *testing.T) {
	t.Parallel()

	tools := getGitHubTools()

	for _, tool := range tools {
		propsMap, valid := validateToolSchema(t, tool)
		if !valid {
			continue
		}

		// Verify tool-specific required fields
		switch tool.Name {
		case "github_get_file", "github_list_directory":
			verifyRequiredFields(t, tool.Name, propsMap, []string{"owner", "repo", "path"})

		case "github_search_code":
			verifyRequiredFields(t, tool.Name, propsMap, []string{"query"})
		}
	}
}
