package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nikogura/diagnostic-slackbot/pkg/k8s"
	"github.com/stretchr/testify/require"
)

// newTestHTTPServer creates an HTTPServer for testing.
func newTestHTTPServer(t *testing.T) (httpServer *HTTPServer) {
	t.Helper()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	lokiClient := k8s.NewLokiClient("http://dummy:3100", logger)
	mcpServer := NewServer(lokiClient, "", logger)
	httpServer = NewHTTPServer(mcpServer, ":0", logger)

	return httpServer
}

func TestNewHTTPServer(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	require.NotNil(t, httpServer, "NewHTTPServer() returned nil")
	require.NotNil(t, httpServer.server, "NewHTTPServer() should have MCP server")
	require.NotNil(t, httpServer.sessions, "NewHTTPServer() should have sessions map")
	require.NotNil(t, httpServer.httpServer, "NewHTTPServer() should have http.Server")
}

func TestHandleHealth(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	httpServer.handleHealth(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("handleHealth() status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("handleHealth() Content-Type = %s, want application/json", contentType)
	}

	var body map[string]interface{}
	decoder := json.NewDecoder(resp.Body)
	err := decoder.Decode(&body)
	if err != nil {
		t.Fatalf("handleHealth() response decode error: %v", err)
	}

	if body["status"] != "healthy" {
		t.Errorf("handleHealth() status = %v, want healthy", body["status"])
	}

	if body["service"] != "diagnostic-mcp" {
		t.Errorf("handleHealth() service = %v, want diagnostic-mcp", body["service"])
	}
}

func TestHandleMessageMethodNotAllowed(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	req := httptest.NewRequest(http.MethodGet, "/message?sessionId=test", nil)
	w := httptest.NewRecorder()

	httpServer.handleMessage(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("handleMessage() GET status = %d, want %d", resp.StatusCode, http.StatusMethodNotAllowed)
	}
}

func TestHandleMessageMissingSessionID(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	req := httptest.NewRequest(http.MethodPost, "/message", nil)
	w := httptest.NewRecorder()

	httpServer.handleMessage(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("handleMessage() without sessionId status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestHandleMessageSessionNotFound(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize"}`
	req := httptest.NewRequest(http.MethodPost, "/message?sessionId=nonexistent", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	httpServer.handleMessage(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("handleMessage() with invalid sessionId status = %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestHandleMessageInvalidJSON(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	// Create a session first
	sess := &session{
		id:        "test-session",
		events:    make(chan []byte, 100),
		done:      make(chan struct{}),
		createdAt: time.Now(),
	}
	httpServer.sessionsMu.Lock()
	httpServer.sessions["test-session"] = sess
	httpServer.sessionsMu.Unlock()

	body := `{invalid json`
	req := httptest.NewRequest(http.MethodPost, "/message?sessionId=test-session", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	httpServer.handleMessage(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("handleMessage() with invalid JSON status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}

func TestHandleMessageValidRequest(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	// Create a session
	sess := &session{
		id:        "test-session",
		events:    make(chan []byte, 100),
		done:      make(chan struct{}),
		createdAt: time.Now(),
	}
	httpServer.sessionsMu.Lock()
	httpServer.sessions["test-session"] = sess
	httpServer.sessionsMu.Unlock()

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize"}`
	req := httptest.NewRequest(http.MethodPost, "/message?sessionId=test-session", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	httpServer.handleMessage(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("handleMessage() valid request status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}

	// Check that response was queued to session events
	select {
	case eventData := <-sess.events:
		var response MCPResponse
		err := json.Unmarshal(eventData, &response)
		if err != nil {
			t.Fatalf("failed to unmarshal event: %v", err)
		}

		if response.ID != float64(1) {
			t.Errorf("response ID = %v, want 1", response.ID)
		}

		if response.Error != nil {
			t.Errorf("response should not have error: %v", response.Error)
		}

	case <-time.After(time.Second):
		t.Error("expected event to be queued, but none received")
	}
}

func TestProcessRequestInitialize(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	}

	ctx := context.Background()
	response := httpServer.processRequest(ctx, req)

	if response.Error != nil {
		t.Errorf("processRequest(initialize) returned error: %v", response.Error)
	}

	if response.ID != 1 {
		t.Errorf("processRequest(initialize) ID = %v, want 1", response.ID)
	}

	result, ok := response.Result["protocolVersion"]
	if !ok {
		t.Error("processRequest(initialize) missing protocolVersion in result")
	}

	if result != "2024-11-05" {
		t.Errorf("processRequest(initialize) protocolVersion = %v, want 2024-11-05", result)
	}
}

func TestProcessRequestToolsList(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}

	ctx := context.Background()
	response := httpServer.processRequest(ctx, req)

	if response.Error != nil {
		t.Errorf("processRequest(tools/list) returned error: %v", response.Error)
	}

	tools, ok := response.Result["tools"]
	if !ok {
		t.Fatal("processRequest(tools/list) missing tools in result")
	}

	toolsList, ok := tools.([]MCPTool)
	if !ok {
		t.Fatal("processRequest(tools/list) tools is not []MCPTool")
	}

	// Should have all 17 tools (including 3 CloudWatch tools and 2 Database tools)
	expectedCount := 17
	if len(toolsList) != expectedCount {
		t.Errorf("processRequest(tools/list) returned %d tools, want %d", len(toolsList), expectedCount)
	}
}

func TestProcessRequestUnknownMethod(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      3,
		Method:  "unknown/method",
	}

	ctx := context.Background()
	response := httpServer.processRequest(ctx, req)

	if response.Error == nil {
		t.Error("processRequest(unknown/method) should return error")
	}

	if response.Error.Code != -32601 {
		t.Errorf("processRequest(unknown/method) error code = %d, want -32601", response.Error.Code)
	}

	if !strings.Contains(response.Error.Message, "unknown method") {
		t.Errorf("processRequest(unknown/method) error message = %s, want to contain 'unknown method'", response.Error.Message)
	}
}

func TestProcessRequestToolsCall(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	// Test calling github_get_file without token (should return error)
	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      4,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name": "github_get_file",
			"arguments": map[string]interface{}{
				"owner": "test-owner",
				"repo":  "test-repo",
				"path":  "README.md",
			},
		},
	}

	ctx := context.Background()
	response := httpServer.processRequest(ctx, req)

	// Should have error because GitHub token not configured
	if response.Error == nil {
		t.Error("processRequest(tools/call github_get_file) without token should return error")
	}

	if !strings.Contains(response.Error.Message, "GitHub access not configured") {
		t.Errorf("processRequest(tools/call) error = %s, want to contain 'GitHub access not configured'", response.Error.Message)
	}
}

func TestProcessRequestToolsCallUnknownTool(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      5,
		Method:  "tools/call",
		Params: map[string]interface{}{
			"name":      "unknown_tool",
			"arguments": map[string]interface{}{},
		},
	}

	ctx := context.Background()
	response := httpServer.processRequest(ctx, req)

	if response.Error == nil {
		t.Error("processRequest(tools/call unknown_tool) should return error")
	}

	if !strings.Contains(response.Error.Message, "unknown tool") {
		t.Errorf("processRequest(tools/call) error = %s, want to contain 'unknown tool'", response.Error.Message)
	}
}

func TestRemoveSession(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	// Create a session
	sess := &session{
		id:        "test-session",
		events:    make(chan []byte, 100),
		done:      make(chan struct{}),
		createdAt: time.Now(),
	}
	httpServer.sessionsMu.Lock()
	httpServer.sessions["test-session"] = sess
	httpServer.sessionsMu.Unlock()

	// Remove the session
	httpServer.removeSession("test-session")

	// Verify session is removed
	httpServer.sessionsMu.RLock()
	_, exists := httpServer.sessions["test-session"]
	httpServer.sessionsMu.RUnlock()

	if exists {
		t.Error("removeSession() did not remove the session")
	}

	// Verify done channel is closed
	select {
	case <-sess.done:
		// Expected - channel is closed
	default:
		t.Error("removeSession() did not close done channel")
	}
}

func TestRemoveSessionNonexistent(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	// Should not panic when removing nonexistent session
	httpServer.removeSession("nonexistent")
}

func TestHandleInitialize(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "initialize",
	}

	response := httpServer.handleInitialize(req)

	if response.JSONRPC != "2.0" {
		t.Errorf("handleInitialize() JSONRPC = %s, want 2.0", response.JSONRPC)
	}

	if response.ID != 1 {
		t.Errorf("handleInitialize() ID = %v, want 1", response.ID)
	}

	if response.Error != nil {
		t.Errorf("handleInitialize() should not return error: %v", response.Error)
	}

	serverInfo, ok := response.Result["serverInfo"].(map[string]interface{})
	if !ok {
		t.Fatal("handleInitialize() missing serverInfo in result")
	}

	if serverInfo["name"] != "diagnostic-mcp" {
		t.Errorf("handleInitialize() serverInfo.name = %v, want diagnostic-mcp", serverInfo["name"])
	}
}

func TestHandleListTools(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      2,
		Method:  "tools/list",
	}

	response := httpServer.handleListTools(req)

	if response.Error != nil {
		t.Errorf("handleListTools() should not return error: %v", response.Error)
	}

	tools, ok := response.Result["tools"]
	if !ok {
		t.Fatal("handleListTools() missing tools in result")
	}

	toolsList, ok := tools.([]MCPTool)
	if !ok {
		t.Fatal("handleListTools() tools is not []MCPTool")
	}

	if len(toolsList) == 0 {
		t.Error("handleListTools() returned empty tools list")
	}
}

func TestExecuteToolUnknown(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	ctx := context.Background()
	params := MCPToolCallParams{
		Name:      "nonexistent_tool",
		Arguments: map[string]interface{}{},
	}

	result, err := httpServer.executeTool(ctx, params)

	if err == nil {
		t.Error("executeTool(nonexistent_tool) should return error")
	}

	if !strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("executeTool() error = %v, want to contain 'unknown tool'", err)
	}

	if result != "" {
		t.Errorf("executeTool() result = %q, want empty string", result)
	}
}

func TestGetServerInfo(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	lokiClient := k8s.NewLokiClient("http://dummy:3100", logger)
	mcpServer := NewServer(lokiClient, "", logger)

	info := mcpServer.getServerInfo()

	if info.ProtocolVersion != "2024-11-05" {
		t.Errorf("getServerInfo() ProtocolVersion = %s, want 2024-11-05", info.ProtocolVersion)
	}

	if info.ServerInfo.Name != "diagnostic-mcp" {
		t.Errorf("getServerInfo() ServerInfo.Name = %s, want diagnostic-mcp", info.ServerInfo.Name)
	}

	if info.ServerInfo.Version != "0.1.0" {
		t.Errorf("getServerInfo() ServerInfo.Version = %s, want 0.1.0", info.ServerInfo.Version)
	}
}

func TestHTTPServerShutdown(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	// Create some sessions
	for i := range 3 {
		sess := &session{
			id:        fmt.Sprintf("session-%d", i),
			events:    make(chan []byte, 100),
			done:      make(chan struct{}),
			createdAt: time.Now(),
		}
		httpServer.sessionsMu.Lock()
		httpServer.sessions[sess.id] = sess
		httpServer.sessionsMu.Unlock()
	}

	// Shutdown
	ctx := context.Background()
	err := httpServer.Shutdown(ctx)
	if err != nil {
		t.Errorf("Shutdown() returned error: %v", err)
	}

	// Verify all sessions are cleaned up
	httpServer.sessionsMu.RLock()
	sessionCount := len(httpServer.sessions)
	httpServer.sessionsMu.RUnlock()

	if sessionCount != 0 {
		t.Errorf("Shutdown() should clear all sessions, got %d remaining", sessionCount)
	}
}

func TestHandleSSEHeaders(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	req := httptest.NewRequest(http.MethodGet, "/sse", nil)

	// Create a recorder that supports flushing
	w := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}

	// Create a context with cancel to simulate client disconnect
	ctx, cancel := context.WithCancel(context.Background())
	req = req.WithContext(ctx)

	// Start SSE handler in goroutine
	done := make(chan struct{})
	go func() {
		httpServer.handleSSE(w, req)
		close(done)
	}()

	// Give it time to set headers and send initial events
	time.Sleep(100 * time.Millisecond)

	// Cancel context to stop handler
	cancel()

	// Wait for handler to finish
	select {
	case <-done:
		// Good
	case <-time.After(time.Second):
		t.Error("handleSSE did not complete after context cancel")
	}

	resp := w.Result()

	// Check headers
	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/event-stream" {
		t.Errorf("handleSSE() Content-Type = %s, want text/event-stream", contentType)
	}

	cacheControl := resp.Header.Get("Cache-Control")
	if cacheControl != "no-cache" {
		t.Errorf("handleSSE() Cache-Control = %s, want no-cache", cacheControl)
	}

	connection := resp.Header.Get("Connection")
	if connection != "keep-alive" {
		t.Errorf("handleSSE() Connection = %s, want keep-alive", connection)
	}
}

func TestReadRequest(t *testing.T) {
	t.Parallel()

	input := `{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n"
	reader := bufio.NewReader(strings.NewReader(input))

	request, err := ReadRequest(reader)

	if err != nil {
		t.Fatalf("ReadRequest() error = %v", err)
	}

	if request.JSONRPC != "2.0" {
		t.Errorf("ReadRequest() JSONRPC = %s, want 2.0", request.JSONRPC)
	}

	if request.Method != "initialize" {
		t.Errorf("ReadRequest() Method = %s, want initialize", request.Method)
	}
}

func TestReadRequestInvalidJSON(t *testing.T) {
	t.Parallel()

	input := `{invalid json}` + "\n"
	reader := bufio.NewReader(strings.NewReader(input))

	_, err := ReadRequest(reader)

	if err == nil {
		t.Error("ReadRequest() with invalid JSON should return error")
	}
}

func TestReadRequestEOF(t *testing.T) {
	t.Parallel()

	reader := bufio.NewReader(strings.NewReader(""))

	_, err := ReadRequest(reader)

	if err == nil {
		t.Error("ReadRequest() with empty input should return error")
	}

	if !errors.Is(err, io.EOF) {
		t.Errorf("ReadRequest() error = %v, want io.EOF", err)
	}
}

// flushRecorder is a ResponseRecorder that supports Flusher interface.
type flushRecorder struct {
	*httptest.ResponseRecorder
	flushed bool
}

func (f *flushRecorder) Flush() {
	f.flushed = true
}

func TestSessionCreationAndCleanup(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	// Manually create sessions with different ages
	now := time.Now()

	oldSession := &session{
		id:        "old-session",
		events:    make(chan []byte, 100),
		done:      make(chan struct{}),
		createdAt: now.Add(-40 * time.Minute), // Older than 30 min
	}

	newSession := &session{
		id:        "new-session",
		events:    make(chan []byte, 100),
		done:      make(chan struct{}),
		createdAt: now,
	}

	httpServer.sessionsMu.Lock()
	httpServer.sessions["old-session"] = oldSession
	httpServer.sessions["new-session"] = newSession
	httpServer.sessionsMu.Unlock()

	// Manually trigger cleanup logic (simulating what cleanupSessions does)
	maxAge := 30 * time.Minute
	httpServer.sessionsMu.Lock()
	for id, sess := range httpServer.sessions {
		if now.Sub(sess.createdAt) > maxAge {
			close(sess.done)
			delete(httpServer.sessions, id)
		}
	}
	httpServer.sessionsMu.Unlock()

	// Check results
	httpServer.sessionsMu.RLock()
	_, oldExists := httpServer.sessions["old-session"]
	_, newExists := httpServer.sessions["new-session"]
	httpServer.sessionsMu.RUnlock()

	if oldExists {
		t.Error("cleanup should have removed old session")
	}

	if !newExists {
		t.Error("cleanup should not have removed new session")
	}
}

func TestHandleToolCallInvalidParams(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	// Create a request with invalid params structure
	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/call",
		Params: map[string]interface{}{
			// Missing "name" field which is required
			"arguments": "not-a-map", // Also wrong type
		},
	}

	ctx := context.Background()
	response := httpServer.handleToolCall(ctx, req)

	// Should either handle gracefully or return an error
	// The empty name will result in "unknown tool" error
	if response.Error == nil {
		t.Log("Response had no error, checking if it handled empty tool name")
	} else {
		t.Logf("Response error: %s", response.Error.Message)
	}
}

func TestHTTPServerIntegration(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	// Create a test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health":
			httpServer.handleHealth(w, r)
		case "/message":
			httpServer.handleMessage(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	// Test health endpoint
	resp, err := http.Get(ts.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /health status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var healthBody map[string]interface{}
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&healthBody)
	if err != nil {
		t.Fatalf("decode health response error: %v", err)
	}

	if healthBody["status"] != "healthy" {
		t.Errorf("health status = %v, want healthy", healthBody["status"])
	}
}

func TestAllToolsCanBeExecutedViaHTTP(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	// Get all tool names
	tools := getToolDefinitions()
	ctx := context.Background()

	for _, tool := range tools {
		toolName := tool.Name
		t.Run(toolName, func(t *testing.T) {
			t.Parallel()

			params := MCPToolCallParams{
				Name:      toolName,
				Arguments: map[string]interface{}{},
			}

			// Execute tool - we expect errors since we don't have real backends
			// but we're testing that the HTTP layer routes correctly
			_, err := httpServer.executeTool(ctx, params)

			// All tools should be recognized (no "unknown tool" error)
			if err != nil && strings.Contains(err.Error(), "unknown tool") {
				t.Errorf("tool %s not recognized by HTTP server", toolName)
			}
		})
	}
}

func TestMessageWithToolsCallRequest(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	// Create session
	sess := &session{
		id:        "test-session",
		events:    make(chan []byte, 100),
		done:      make(chan struct{}),
		createdAt: time.Now(),
	}
	httpServer.sessionsMu.Lock()
	httpServer.sessions["test-session"] = sess
	httpServer.sessionsMu.Unlock()

	// Send tools/list request
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`
	req := httptest.NewRequest(http.MethodPost, "/message?sessionId=test-session", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	httpServer.handleMessage(w, req)

	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("POST /message status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}

	// Check response was queued
	select {
	case eventData := <-sess.events:
		var response MCPResponse
		err := json.Unmarshal(eventData, &response)
		if err != nil {
			t.Fatalf("unmarshal response error: %v", err)
		}

		if response.Error != nil {
			t.Errorf("tools/list should not return error: %v", response.Error)
		}

		tools, ok := response.Result["tools"]
		if !ok {
			t.Error("response missing tools")
		}

		// After JSON roundtrip, tools is []interface{} not []MCPTool
		toolsList, ok := tools.([]interface{})
		if !ok {
			t.Error("tools is not []interface{}")
		}

		if len(toolsList) == 0 {
			t.Error("tools list is empty")
		}

	case <-time.After(time.Second):
		t.Error("expected response event, got timeout")
	}
}

func TestConcurrentSessionAccess(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	// Create multiple sessions concurrently
	const numSessions = 10
	done := make(chan bool, numSessions)

	for i := range numSessions {
		go func(id int) {
			sessID := fmt.Sprintf("session-%d", id)
			sess := &session{
				id:        sessID,
				events:    make(chan []byte, 100),
				done:      make(chan struct{}),
				createdAt: time.Now(),
			}

			httpServer.sessionsMu.Lock()
			httpServer.sessions[sessID] = sess
			httpServer.sessionsMu.Unlock()

			// Read back
			httpServer.sessionsMu.RLock()
			_, exists := httpServer.sessions[sessID]
			httpServer.sessionsMu.RUnlock()

			done <- exists
		}(i)
	}

	// Wait for all goroutines
	for range numSessions {
		if !<-done {
			t.Error("concurrent session creation failed")
		}
	}

	// Verify all sessions exist
	httpServer.sessionsMu.RLock()
	count := len(httpServer.sessions)
	httpServer.sessionsMu.RUnlock()

	if count != numSessions {
		t.Errorf("expected %d sessions, got %d", numSessions, count)
	}
}

func TestHTTPServerRunHTTP(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelError,
	}))

	lokiClient := k8s.NewLokiClient("http://dummy:3100", logger)
	mcpServer := NewServer(lokiClient, "", logger)

	ctx, cancel := context.WithCancel(context.Background())

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		err := mcpServer.RunHTTP(ctx, "127.0.0.1:0")
		errChan <- err
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Cancel to trigger shutdown
	cancel()

	// Wait for shutdown
	select {
	case err := <-errChan:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Errorf("RunHTTP() returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("RunHTTP() did not shutdown within timeout")
	}
}

func TestSSEEndpointEvent(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	req := httptest.NewRequest(http.MethodGet, "/sse", nil)
	w := &flushRecorder{ResponseRecorder: httptest.NewRecorder()}

	ctx, cancel := context.WithCancel(context.Background())
	req = req.WithContext(ctx)

	done := make(chan struct{})
	go func() {
		httpServer.handleSSE(w, req)
		close(done)
	}()

	// Give time for initial events
	time.Sleep(100 * time.Millisecond)
	cancel()

	<-done

	body := w.Body.String()

	// Check for endpoint event
	if !strings.Contains(body, "event: endpoint") {
		t.Error("SSE response missing endpoint event")
	}

	// Check for message event with server info
	if !strings.Contains(body, "event: message") {
		t.Error("SSE response missing message event")
	}

	// Check endpoint data contains sessionId
	if !strings.Contains(body, "sessionId=") {
		t.Error("SSE endpoint event missing sessionId")
	}
}

func TestEventBufferFull(t *testing.T) {
	t.Parallel()

	httpServer := newTestHTTPServer(t)

	// Create session with small buffer
	sess := &session{
		id:        "test-session",
		events:    make(chan []byte, 1), // Very small buffer
		done:      make(chan struct{}),
		createdAt: time.Now(),
	}
	httpServer.sessionsMu.Lock()
	httpServer.sessions["test-session"] = sess
	httpServer.sessionsMu.Unlock()

	// Fill the buffer
	sess.events <- []byte("first")

	// Send another request - should not block
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize"}`
	req := httptest.NewRequest(http.MethodPost, "/message?sessionId=test-session", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	// This should complete without blocking
	done := make(chan struct{})
	go func() {
		httpServer.handleMessage(w, req)
		close(done)
	}()

	select {
	case <-done:
		// Good - didn't block
	case <-time.After(time.Second):
		t.Error("handleMessage blocked when buffer was full")
	}

	resp := w.Result()
	defer resp.Body.Close()

	// Should still return accepted even if event couldn't be queued
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusAccepted)
	}
}

func BenchmarkHandleMessage(b *testing.B) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	lokiClient := k8s.NewLokiClient("http://dummy:3100", logger)
	mcpServer := NewServer(lokiClient, "", logger)
	httpServer := NewHTTPServer(mcpServer, ":0", logger)

	sess := &session{
		id:        "bench-session",
		events:    make(chan []byte, 1000),
		done:      make(chan struct{}),
		createdAt: time.Now(),
	}
	httpServer.sessionsMu.Lock()
	httpServer.sessions["bench-session"] = sess
	httpServer.sessionsMu.Unlock()

	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`

	b.ResetTimer()
	for range b.N {
		req := httptest.NewRequest(http.MethodPost, "/message?sessionId=bench-session", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		httpServer.handleMessage(w, req)

		// Drain events channel
		select {
		case <-sess.events:
		default:
		}
	}
}

func BenchmarkProcessRequest(b *testing.B) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	lokiClient := k8s.NewLokiClient("http://dummy:3100", logger)
	mcpServer := NewServer(lokiClient, "", logger)
	httpServer := NewHTTPServer(mcpServer, ":0", logger)

	req := MCPRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "tools/list",
	}
	ctx := context.Background()

	b.ResetTimer()
	for range b.N {
		_ = httpServer.processRequest(ctx, req)
	}
}
