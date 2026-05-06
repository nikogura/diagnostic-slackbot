package apiconfig

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestAPIToolRegistry_GetToolDefinitions(t *testing.T) {
	t.Parallel()

	configs := []*APIConfig{
		{
			Name:    "testapi",
			BaseURL: "https://example.com",
			Endpoints: []Endpoint{
				{Name: "list_items", Description: "List items", Path: "/items"},
				{Name: "get_item", Description: "Get item", Path: "/items/{id}", Params: []Param{
					{Name: "id", Type: "string", Required: true, In: "path"},
				}},
			},
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewAPIToolRegistry(configs, logger)

	tools := registry.GetToolDefinitions()

	if len(tools) != 2 {
		t.Fatalf("expected 2 tools, got %d", len(tools))
	}

	if tools[0].Name != "testapi_list_items" {
		t.Errorf("expected tool name 'testapi_list_items', got %q", tools[0].Name)
	}

	if tools[1].Name != "testapi_get_item" {
		t.Errorf("expected tool name 'testapi_get_item', got %q", tools[1].Name)
	}

	// Check that required param is in schema
	schema := tools[1].InputSchema
	requiredRaw, ok := schema["required"]
	if !ok {
		t.Fatal("expected 'required' in schema")
	}

	required, castOk := requiredRaw.([]string)
	if !castOk {
		t.Fatal("expected required to be []string")
	}

	if len(required) != 1 || required[0] != "id" {
		t.Errorf("expected required=['id'], got %v", required)
	}
}

func TestAPIToolRegistry_DispatchToolCall(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"items":[]}`))
	}))
	defer server.Close()

	t.Setenv("DISPATCH_TOKEN", "tok")

	configs := []*APIConfig{
		{
			Name:    "myapi",
			BaseURL: server.URL,
			Auth:    AuthConfig{Type: AuthTypeBearer, TokenEnv: "DISPATCH_TOKEN"},
			Endpoints: []Endpoint{
				{Name: "list", Method: "GET", Path: "/items"},
			},
			RateLimit: RateLimitConfig{MaxConcurrent: 5, MaxRetries: 1},
			Defaults:  DefaultsConfig{Limit: 25, MaxLimit: 100},
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewAPIToolRegistry(configs, logger)

	result, handled, err := registry.DispatchToolCall(context.Background(), "myapi_list", map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !handled {
		t.Error("expected handled=true")
	}

	if result != `{"items":[]}` {
		t.Errorf("unexpected result: %s", result)
	}

	// Unknown tool should not be handled
	_, handled, _ = registry.DispatchToolCall(context.Background(), "unknown_tool", map[string]interface{}{})
	if handled {
		t.Error("expected handled=false for unknown tool")
	}
}

func TestAPIToolRegistry_WriteToolUsage(t *testing.T) {
	t.Parallel()

	configs := []*APIConfig{
		{
			Name: "bitgo",
			Endpoints: []Endpoint{
				{Name: "list_wallets", Description: "List wallets"},
				{Name: "get_wallet", Description: "Get wallet details"},
			},
		},
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	registry := NewAPIToolRegistry(configs, logger)

	var builder strings.Builder
	registry.WriteToolUsage(&builder)

	output := builder.String()

	if !strings.Contains(output, "bitgo API") {
		t.Errorf("expected 'bitgo API' in output, got: %s", output)
	}

	if !strings.Contains(output, "bitgo_list_wallets") {
		t.Errorf("expected 'bitgo_list_wallets' in output, got: %s", output)
	}

	if !strings.Contains(output, "bitgo_get_wallet") {
		t.Errorf("expected 'bitgo_get_wallet' in output, got: %s", output)
	}
}

func TestAPIToolRegistry_HasTools(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	emptyRegistry := NewAPIToolRegistry(nil, logger)
	if emptyRegistry.HasTools() {
		t.Error("expected HasTools()=false for empty registry")
	}

	withConfigs := NewAPIToolRegistry([]*APIConfig{{Name: "test", Endpoints: []Endpoint{{Name: "a", Path: "/a"}}}}, logger)
	if !withConfigs.HasTools() {
		t.Error("expected HasTools()=true with configs")
	}
}
