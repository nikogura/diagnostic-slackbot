package mcp

import (
	"context"
	"log/slog"
	"net/http/httptest"
	"os"
	"testing"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"
)

func newTestSDKServer(t *testing.T) (sdkServer *SDKServer) {
	t.Helper()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	// Create a minimal legacy server with no backends — only utility tools will register
	legacy := &Server{
		logger:      logger,
		companyName: "TestCorp",
	}

	sdkServer = NewSDKServer(legacy)

	return sdkServer
}

func TestSDKServerStreamableHTTP(t *testing.T) {
	t.Parallel()

	sdkServer := newTestSDKServer(t)

	// Start test HTTP server with Streamable HTTP handler
	ts := httptest.NewServer(sdkServer.StreamableHTTPHandler())
	defer ts.Close()

	ctx := context.Background()

	// Create SDK client
	client := sdkmcp.NewClient(&sdkmcp.Implementation{
		Name:    "test-client",
		Version: "0.0.1",
	}, nil)

	// Connect via Streamable HTTP
	session, err := client.Connect(ctx, &sdkmcp.StreamableClientTransport{
		Endpoint: ts.URL,
	}, nil)
	require.NoError(t, err)
	defer session.Close()

	// List tools
	toolsResult, err := session.ListTools(ctx, nil)
	require.NoError(t, err)
	require.NotEmpty(t, toolsResult.Tools, "expected at least utility tools to be registered")

	// Verify whois_lookup tool exists
	foundWhois := false
	for _, tool := range toolsResult.Tools {
		if tool.Name == "whois_lookup" {
			foundWhois = true
			break
		}
	}
	require.True(t, foundWhois, "whois_lookup tool should be registered")
}

func TestSDKServerSSE(t *testing.T) {
	t.Parallel()

	sdkServer := newTestSDKServer(t)

	// Start test HTTP server with SSE handler
	ts := httptest.NewServer(sdkServer.SSEHandler())
	defer ts.Close()

	ctx := context.Background()

	// Create SDK client
	client := sdkmcp.NewClient(&sdkmcp.Implementation{
		Name:    "test-client",
		Version: "0.0.1",
	}, nil)

	// Connect via SSE
	session, err := client.Connect(ctx, &sdkmcp.SSEClientTransport{
		Endpoint: ts.URL,
	}, nil)
	require.NoError(t, err)
	defer session.Close()

	// List tools
	toolsResult, err := session.ListTools(ctx, nil)
	require.NoError(t, err)
	require.NotEmpty(t, toolsResult.Tools, "expected at least utility tools to be registered")

	// Verify whois_lookup tool exists
	foundWhois := false
	for _, tool := range toolsResult.Tools {
		if tool.Name == "whois_lookup" {
			foundWhois = true
			break
		}
	}
	require.True(t, foundWhois, "whois_lookup tool should be registered")
}

func TestSDKServerToolCall(t *testing.T) {
	t.Parallel()

	sdkServer := newTestSDKServer(t)

	ts := httptest.NewServer(sdkServer.StreamableHTTPHandler())
	defer ts.Close()

	ctx := context.Background()

	client := sdkmcp.NewClient(&sdkmcp.Implementation{
		Name:    "test-client",
		Version: "0.0.1",
	}, nil)

	session, err := client.Connect(ctx, &sdkmcp.StreamableClientTransport{
		Endpoint: ts.URL,
	}, nil)
	require.NoError(t, err)
	defer session.Close()

	// Call generate_pdf which will fail (no pandoc in test), but exercises the dispatch path
	result, err := session.CallTool(ctx, &sdkmcp.CallToolParams{
		Name: "generate_pdf",
		Arguments: map[string]any{
			"markdown_content": "# Test",
			"filename":         "test",
		},
	})

	// The tool should be dispatched (no "unknown tool" error)
	// It will fail because pandoc isn't available, but that's the handler running
	if err != nil {
		require.NotContains(t, err.Error(), "unknown tool", "tool should be registered and dispatched")
	} else {
		require.NotNil(t, result)
	}
}

func TestSDKServerBothTransportsSameTools(t *testing.T) {
	t.Parallel()

	sdkServer := newTestSDKServer(t)

	// Start both handlers
	tsStreamable := httptest.NewServer(sdkServer.StreamableHTTPHandler())
	defer tsStreamable.Close()

	tsSSE := httptest.NewServer(sdkServer.SSEHandler())
	defer tsSSE.Close()

	ctx := context.Background()

	// Connect via Streamable HTTP
	clientHTTP := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "http-client", Version: "0.0.1"}, nil)
	sessionHTTP, err := clientHTTP.Connect(ctx, &sdkmcp.StreamableClientTransport{Endpoint: tsStreamable.URL}, nil)
	require.NoError(t, err)
	defer sessionHTTP.Close()

	// Connect via SSE
	clientSSE := sdkmcp.NewClient(&sdkmcp.Implementation{Name: "sse-client", Version: "0.0.1"}, nil)
	sessionSSE, err := clientSSE.Connect(ctx, &sdkmcp.SSEClientTransport{Endpoint: tsSSE.URL}, nil)
	require.NoError(t, err)
	defer sessionSSE.Close()

	// Both should return the same tools
	toolsHTTP, err := sessionHTTP.ListTools(ctx, nil)
	require.NoError(t, err)

	toolsSSE, err := sessionSSE.ListTools(ctx, nil)
	require.NoError(t, err)

	require.Len(t, toolsSSE.Tools, len(toolsHTTP.Tools),
		"both transports should expose the same number of tools")

	// Build name sets
	httpNames := make(map[string]bool)
	for _, tool := range toolsHTTP.Tools {
		httpNames[tool.Name] = true
	}

	for _, tool := range toolsSSE.Tools {
		require.True(t, httpNames[tool.Name],
			"SSE tool %q should also be in Streamable HTTP tools", tool.Name)
	}
}
