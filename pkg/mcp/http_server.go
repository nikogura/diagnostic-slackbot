package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nikogura/diagnostic-slackbot/pkg/mcp/auth"
)

// HTTPServer wraps an MCP Server with HTTP/SSE transport.
type HTTPServer struct {
	server     *Server
	logger     *slog.Logger
	httpServer *http.Server
	sessions   map[string]*session
	sessionsMu sync.RWMutex
	authChain  *auth.Chain // Authentication chain
}

// session represents an active SSE client session.
type session struct {
	id        string
	events    chan []byte
	done      chan struct{}
	createdAt time.Time
}

// NewHTTPServer creates a new HTTP server wrapping the MCP server.
// authChain can be nil to disable authentication.
func NewHTTPServer(mcpServer *Server, addr string, authChain *auth.Chain, logger *slog.Logger) (result *HTTPServer) {
	result = &HTTPServer{
		server:    mcpServer,
		logger:    logger,
		sessions:  make(map[string]*session),
		authChain: authChain,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/auth", result.handleAuth)
	mux.HandleFunc("/sse", result.handleSSE)
	mux.HandleFunc("/message", result.handleMessage)
	mux.HandleFunc("/health", result.handleHealth)

	result.httpServer = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	return result
}

// Start starts the HTTP server.
func (h *HTTPServer) Start(ctx context.Context) (err error) {
	h.logger.InfoContext(ctx, "starting MCP HTTP server", slog.String("addr", h.httpServer.Addr))

	// Start session cleanup goroutine
	go h.cleanupSessions(ctx)

	err = h.httpServer.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return err
	}

	err = nil
	return err
}

// Shutdown gracefully shuts down the HTTP server.
func (h *HTTPServer) Shutdown(ctx context.Context) (err error) {
	h.logger.InfoContext(ctx, "shutting down MCP HTTP server")

	// Close all sessions
	h.sessionsMu.Lock()
	for _, sess := range h.sessions {
		close(sess.done)
	}
	h.sessions = make(map[string]*session)
	h.sessionsMu.Unlock()

	err = h.httpServer.Shutdown(ctx)
	return err
}

// handleHealth returns server health status.
func (h *HTTPServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	response := map[string]interface{}{
		"status":  "healthy",
		"service": "diagnostic-mcp",
	}

	encoder := json.NewEncoder(w)
	_ = encoder.Encode(response)
}

// handleAuth handles authentication requests using the auth chain.
// If no auth is configured, always returns success (auth disabled).
func (h *HTTPServer) handleAuth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// If no auth chain configured, authentication is disabled
	if h.authChain == nil {
		w.WriteHeader(http.StatusOK)
		response := map[string]interface{}{
			"authenticated": true,
			"message":       "Authentication disabled - no methods configured",
		}
		encoder := json.NewEncoder(w)
		_ = encoder.Encode(response)
		return
	}

	// Try authentication
	result, err := h.authChain.Authenticate(r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		response := map[string]interface{}{
			"authenticated": false,
			"error":         err.Error(),
		}
		encoder := json.NewEncoder(w)
		_ = encoder.Encode(response)
		return
	}

	// Successfully authenticated
	w.WriteHeader(http.StatusOK)
	encoder := json.NewEncoder(w)
	_ = encoder.Encode(result)
}

// handleSSE handles Server-Sent Events connections.
func (h *HTTPServer) handleSSE(w http.ResponseWriter, r *http.Request) {
	// Check for SSE support
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	// Create new session
	sess := &session{
		id:        uuid.New().String(),
		events:    make(chan []byte, 100),
		done:      make(chan struct{}),
		createdAt: time.Now(),
	}

	h.sessionsMu.Lock()
	h.sessions[sess.id] = sess
	h.sessionsMu.Unlock()

	h.logger.Info("new SSE session created", slog.String("session_id", sess.id))

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Send endpoint event with session info
	endpointEvent := fmt.Sprintf("event: endpoint\ndata: /message?sessionId=%s\n\n", sess.id)
	_, writeErr := w.Write([]byte(endpointEvent))
	if writeErr != nil {
		h.logger.Error("failed to write endpoint event", slog.String("error", writeErr.Error()))
		return
	}
	flusher.Flush()

	// Send initial server info
	serverInfo := h.server.getServerInfo()
	serverInfoBytes, _ := json.Marshal(serverInfo)
	initEvent := fmt.Sprintf("event: message\ndata: %s\n\n", string(serverInfoBytes))
	_, writeErr = w.Write([]byte(initEvent))
	if writeErr != nil {
		h.logger.Error("failed to write init event", slog.String("error", writeErr.Error()))
		return
	}
	flusher.Flush()

	// Stream events until connection closes
	for {
		select {
		case <-r.Context().Done():
			h.removeSession(sess.id)
			h.logger.Info("SSE session closed by client", slog.String("session_id", sess.id))
			return

		case <-sess.done:
			h.logger.Info("SSE session closed by server", slog.String("session_id", sess.id))
			return

		case eventData := <-sess.events:
			event := fmt.Sprintf("event: message\ndata: %s\n\n", string(eventData))
			_, writeErr = w.Write([]byte(event))
			if writeErr != nil {
				h.removeSession(sess.id)
				h.logger.Error("failed to write event", slog.String("error", writeErr.Error()))
				return
			}
			flusher.Flush()
		}
	}
}

// handleMessage handles incoming MCP messages.
func (h *HTTPServer) handleMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get session ID from query parameter
	sessionID := r.URL.Query().Get("sessionId")
	if sessionID == "" {
		http.Error(w, "sessionId query parameter required", http.StatusBadRequest)
		return
	}

	// Find session
	h.sessionsMu.RLock()
	sess, exists := h.sessions[sessionID]
	h.sessionsMu.RUnlock()

	if !exists {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	// Parse request
	var request MCPRequest
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&request)
	if err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	h.logger.Info("received MCP request",
		slog.String("session_id", sessionID),
		slog.String("method", request.Method),
		slog.Any("id", request.ID))

	// Process request and get response
	response := h.processRequest(r.Context(), request)

	// Send response via SSE
	responseBytes, _ := json.Marshal(response)
	select {
	case sess.events <- responseBytes:
		// Successfully queued
	default:
		h.logger.Warn("session event buffer full", slog.String("session_id", sessionID))
	}

	// Also return accepted status
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)

	acceptedResponse := map[string]string{"status": "accepted"}
	encoder := json.NewEncoder(w)
	_ = encoder.Encode(acceptedResponse)
}

// processRequest processes an MCP request and returns a response.
func (h *HTTPServer) processRequest(ctx context.Context, req MCPRequest) (response MCPResponse) {
	switch req.Method {
	case methodInitialize:
		response = h.handleInitialize(req)

	case methodToolsList:
		response = h.handleListTools(req)

	case methodToolsCall:
		response = h.handleToolCall(ctx, req)

	default:
		response = MCPResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &MCPError{
				Code:    -32601,
				Message: fmt.Sprintf("unknown method: %s", req.Method),
			},
		}
	}

	return response
}

// handleInitialize handles the initialize request.
func (h *HTTPServer) handleInitialize(req MCPRequest) (response MCPResponse) {
	response = MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			"serverInfo": map[string]interface{}{
				"name":    "diagnostic-mcp",
				"version": "0.1.0",
			},
		},
	}
	return response
}

// handleListTools handles the tools/list request.
func (h *HTTPServer) handleListTools(req MCPRequest) (response MCPResponse) {
	tools := getToolDefinitions()

	response = MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"tools": tools,
		},
	}
	return response
}

// handleToolCall handles the tools/call request.
func (h *HTTPServer) handleToolCall(ctx context.Context, req MCPRequest) (response MCPResponse) {
	var params MCPToolCallParams

	paramsJSON, _ := json.Marshal(req.Params)
	err := json.Unmarshal(paramsJSON, &params)
	if err != nil {
		response = MCPResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &MCPError{
				Code:    -32602,
				Message: fmt.Sprintf("invalid params: %v", err),
			},
		}
		return response
	}

	h.logger.InfoContext(ctx, "executing tool via HTTP", slog.String("tool", params.Name))

	result, err := h.executeTool(ctx, params)
	if err != nil {
		response = MCPResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &MCPError{
				Code:    -32603,
				Message: fmt.Sprintf("tool execution error: %v", err),
			},
		}
		return response
	}

	response = MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": result,
				},
			},
		},
	}
	return response
}

// executeTool executes a tool by name.
func (h *HTTPServer) executeTool(ctx context.Context, params MCPToolCallParams) (result string, err error) {
	switch params.Name {
	case toolQueryLoki:
		result, err = h.server.executeQueryLoki(ctx, params.Arguments)

	case toolWhoisLookup:
		result, err = h.server.executeWhoisLookup(ctx, params.Arguments)

	case toolGeneratePDF:
		result, err = h.server.executeGeneratePDF(ctx, params.Arguments)

	case toolGitHubGetFile:
		result, err = h.server.executeGitHubGetFile(ctx, params.Arguments)

	case toolGitHubListDirectory:
		result, err = h.server.executeGitHubListDirectory(ctx, params.Arguments)

	case toolGitHubSearchCode:
		result, err = h.server.executeGitHubSearchCode(ctx, params.Arguments)

	case toolECRScanResults:
		result, err = h.server.executeECRScanResults(ctx, params.Arguments)

	case toolDatabaseQuery:
		result, err = h.server.executeDatabaseQuery(ctx, params.Arguments)

	case toolDatabaseList:
		result, err = h.server.executeDatabaseList(ctx, params.Arguments)

	case toolGrafanaListDashboards:
		result, err = h.server.executeGrafanaListDashboards(ctx, params.Arguments)

	case toolGrafanaGetDashboard:
		result, err = h.server.executeGrafanaGetDashboard(ctx, params.Arguments)

	case toolGrafanaCreateDashboard:
		result, err = h.server.executeGrafanaCreateDashboard(ctx, params.Arguments)

	case toolGrafanaUpdateDashboard:
		result, err = h.server.executeGrafanaUpdateDashboard(ctx, params.Arguments)

	case toolGrafanaDeleteDashboard:
		result, err = h.server.executeGrafanaDeleteDashboard(ctx, params.Arguments)

	case toolCloudWatchLogsQuery:
		result, err = h.server.executeCloudWatchLogsQuery(ctx, params.Arguments)

	case toolCloudWatchLogsListGroups:
		result, err = h.server.executeCloudWatchLogsListGroups(ctx, params.Arguments)

	case toolCloudWatchLogsGetEvents:
		result, err = h.server.executeCloudWatchLogsGetEvents(ctx, params.Arguments)

	case toolPrometheusQuery:
		result, err = h.server.executePrometheusQuery(ctx, params.Arguments)

	case toolPrometheusQueryRange:
		result, err = h.server.executePrometheusQueryRange(ctx, params.Arguments)

	case toolPrometheusSeries:
		result, err = h.server.executePrometheusSeries(ctx, params.Arguments)

	case toolPrometheusLabelValues:
		result, err = h.server.executePrometheusLabelValues(ctx, params.Arguments)

	case toolPrometheusListEndpoints:
		result, err = h.server.executePrometheusListEndpoints(ctx, params.Arguments)

	default:
		err = fmt.Errorf("unknown tool: %s", params.Name)
	}

	return result, err
}

// removeSession removes a session from the sessions map.
func (h *HTTPServer) removeSession(sessionID string) {
	h.sessionsMu.Lock()
	defer h.sessionsMu.Unlock()

	if sess, exists := h.sessions[sessionID]; exists {
		close(sess.done)
		delete(h.sessions, sessionID)
	}
}

// cleanupSessions periodically removes stale sessions.
func (h *HTTPServer) cleanupSessions(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	maxAge := 30 * time.Minute

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			h.sessionsMu.Lock()
			now := time.Now()
			for id, sess := range h.sessions {
				if now.Sub(sess.createdAt) > maxAge {
					h.logger.InfoContext(ctx, "cleaning up stale session", slog.String("session_id", id))
					close(sess.done)
					delete(h.sessions, id)
				}
			}
			h.sessionsMu.Unlock()
		}
	}
}

// getServerInfo returns the MCP server info structure.
func (s *Server) getServerInfo() (info MCPServerInfo) {
	info = MCPServerInfo{
		ProtocolVersion: "2024-11-05",
		Capabilities: MCPCapabilities{
			Tools: map[string]interface{}{},
		},
		ServerInfo: ServerMetadata{
			Name:    "diagnostic-mcp",
			Version: "0.1.0",
		},
	}
	return info
}

// RunHTTP starts the MCP server with HTTP transport (alternative to stdio Run).
// If authChain is nil, authentication is disabled.
func (s *Server) RunHTTP(ctx context.Context, addr string, authChain *auth.Chain) (err error) {
	httpServer := NewHTTPServer(s, addr, authChain, s.logger)

	// Handle shutdown
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	err = httpServer.Start(ctx)
	return err
}

// ReadRequest reads and parses an MCP request from a buffered reader.
// Useful for testing stdio transport.
func ReadRequest(reader *bufio.Reader) (request MCPRequest, err error) {
	var line []byte
	line, err = reader.ReadBytes('\n')
	if err != nil {
		return request, err
	}

	err = json.Unmarshal(line, &request)
	return request, err
}
