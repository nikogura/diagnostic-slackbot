package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/go-github/v57/github"
	"github.com/nikogura/diagnostic-slackbot/pkg/k8s"
	"golang.org/x/oauth2"
)

// Server implements the MCP (Model Context Protocol) server.
type Server struct {
	lokiClient   *k8s.LokiClient
	githubClient *github.Client
	logger       *slog.Logger
	companyName  string
}

// NewServer creates a new MCP server.
func NewServer(lokiClient *k8s.LokiClient, githubToken string, logger *slog.Logger) (result *Server) {
	var githubClient *github.Client

	if githubToken != "" {
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: githubToken},
		)
		tc := oauth2.NewClient(context.Background(), ts)
		githubClient = github.NewClient(tc)
		logger.Info("GitHub client initialized")
	} else {
		logger.Warn("GitHub token not provided - GitHub tools will be unavailable")
	}

	// Get company name from environment, default to "Company"
	companyName := os.Getenv("COMPANY_NAME")
	if companyName == "" {
		companyName = "Company"
	}

	result = &Server{
		lokiClient:   lokiClient,
		githubClient: githubClient,
		logger:       logger,
		companyName:  companyName,
	}

	return result
}

// Run starts the MCP server using stdio transport.
func (s *Server) Run(ctx context.Context) (err error) {
	scanner := bufio.NewScanner(os.Stdin)

	s.logger.InfoContext(ctx, "MCP server started", slog.String("transport", "stdio"))

	// Send server info
	s.sendServerInfo()

	for scanner.Scan() {
		line := scanner.Bytes()

		var request MCPRequest

		err = json.Unmarshal(line, &request)
		if err != nil {
			s.logger.WarnContext(ctx, "failed to parse request", slog.String("error", err.Error()))
			continue
		}

		s.handleRequest(ctx, request)
	}

	err = scanner.Err()
	if err != nil {
		err = fmt.Errorf("reading stdin: %w", err)
		return err
	}

	return err
}

// sendServerInfo sends the server capabilities to Claude Code.
func (s *Server) sendServerInfo() {
	info := MCPServerInfo{
		ProtocolVersion: "2024-11-05",
		Capabilities: MCPCapabilities{
			Tools: map[string]interface{}{},
		},
		ServerInfo: ServerMetadata{
			Name:    "diagnostic-mcp",
			Version: "0.1.0",
		},
	}

	data, _ := json.Marshal(info)
	fmt.Println(string(data))
}

// handleRequest processes an MCP request.
func (s *Server) handleRequest(ctx context.Context, req MCPRequest) {
	switch req.Method {
	case "initialize":
		s.handleInitialize(ctx, req)

	case "tools/list":
		s.handleListTools(ctx, req)

	case "tools/call":
		s.handleToolCall(ctx, req)

	default:
		s.sendError(req.ID, fmt.Sprintf("unknown method: %s", req.Method))
	}
}

// handleInitialize handles the MCP initialize request.
func (s *Server) handleInitialize(_ context.Context, req MCPRequest) {
	response := MCPResponse{
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

	data, _ := json.Marshal(response)
	fmt.Println(string(data))
}

// getLokiTools returns Loki-related tool definitions.
func getLokiTools() (result []MCPTool) {
	result = []MCPTool{
		{
			Name:        "query_loki",
			Description: "Query Loki log aggregation system for ModSecurity WAF logs. Returns JSON log entries with transaction details, blocked IPs, rule IDs, etc.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]interface{}{
						"type":        "string",
						"description": "LogQL query string. Example: '{realm=\"prod\", namespace=\"ingress-nginx\"} |~ \"ModSecurity\" | json | transaction_response_http_code=\"403\"'",
					},
					"start": map[string]interface{}{
						"type":        "string",
						"description": "Start time as relative duration (e.g., '1h', '24h') or RFC3339 timestamp",
					},
					"end": map[string]interface{}{
						"type":        "string",
						"description": "End time as 'now' or RFC3339 timestamp (optional, defaults to now)",
					},
					"limit": map[string]interface{}{
						"type":        "integer",
						"description": "Maximum number of log entries to return (default: 100, recommended max: 500 to avoid token limits)",
					},
				},
				"required": []string{"query", "start"},
			},
		},
	}

	return result
}

// getUtilityTools returns utility tool definitions (whois, PDF generation).
func getUtilityTools() (result []MCPTool) {
	result = []MCPTool{
		{
			Name:        "whois_lookup",
			Description: "Perform whois lookup on an IP address to determine geolocation, ISP, ASN, and organization. Useful for analyzing blocked IPs to determine if they're VPNs, cloud providers, or suspicious sources.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"ip_address": map[string]interface{}{
						"type":        "string",
						"description": "IP address to look up (IPv4 format, e.g., '192.168.1.1')",
					},
				},
				"required": []string{"ip_address"},
			},
		},
		{
			Name:        "generate_pdf",
			Description: "Generate a PDF report from Markdown content using pandoc with LaTeX. The PDF will be saved to /tmp/ and automatically uploaded to Slack. ALWAYS use this tool for report generation to provide downloadable reports.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"markdown_content": map[string]interface{}{
						"type":        "string",
						"description": "Markdown content to convert to PDF. Use standard Markdown formatting (headers, tables, lists, bold, italic, code blocks). Tables are supported.",
					},
					"filename": map[string]interface{}{
						"type":        "string",
						"description": "Output filename (without path, .pdf extension will be added if missing). Example: 'modsecurity_report_2025-01-10'",
					},
					"title": map[string]interface{}{
						"type":        "string",
						"description": "Report title for PDF metadata",
					},
				},
				"required": []string{"markdown_content", "filename"},
			},
		},
	}

	return result
}

// getGitHubTools returns GitHub-related tool definitions.
func getGitHubTools() (result []MCPTool) {
	result = []MCPTool{
		{
			Name:        "github_get_file",
			Description: "Fetch a file from a GitHub repository. Useful for reading database schema files, migration files, or configuration. Requires GITHUB_TOKEN to be configured.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"owner": map[string]interface{}{
						"type":        "string",
						"description": "Repository owner (e.g., 'your-org')",
					},
					"repo": map[string]interface{}{
						"type":        "string",
						"description": "Repository name (e.g., 'example-api')",
					},
					"path": map[string]interface{}{
						"type":        "string",
						"description": "File path within repository (e.g., 'db/schema.hcl' or 'db/migrations/20250101_add_users.sql')",
					},
					"ref": map[string]interface{}{
						"type":        "string",
						"description": "Git ref (branch, tag, or commit SHA). Defaults to 'main' if not provided",
					},
				},
				"required": []string{"owner", "repo", "path"},
			},
		},
		{
			Name:        "github_list_directory",
			Description: "List files in a GitHub repository directory. Useful for discovering migration files or schema versions. Requires GITHUB_TOKEN to be configured.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"owner": map[string]interface{}{
						"type":        "string",
						"description": "Repository owner (e.g., 'your-org')",
					},
					"repo": map[string]interface{}{
						"type":        "string",
						"description": "Repository name (e.g., 'example-api')",
					},
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Directory path (e.g., 'db/migrations')",
					},
					"ref": map[string]interface{}{
						"type":        "string",
						"description": "Git ref (branch, tag, or commit SHA). Defaults to 'main' if not provided",
					},
				},
				"required": []string{"owner", "repo", "path"},
			},
		},
		{
			Name:        "github_search_code",
			Description: "Search for code across GitHub repositories. Useful for finding migration patterns or schema references. Requires GITHUB_TOKEN to be configured.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]interface{}{
						"type":        "string",
						"description": "Search query using GitHub code search syntax (e.g., 'table users repo:your-org/example-api path:db/migrations')",
					},
				},
				"required": []string{"query"},
			},
		},
	}

	return result
}

// getECRTools returns ECR-related tool definitions.
func getECRTools() (result []MCPTool) {
	result = []MCPTool{
		{
			Name:        "ecr_scan_results",
			Description: "Query AWS ECR for container image vulnerability scan results across multiple accounts. Returns vulnerability findings with severity levels (CRITICAL, HIGH, MEDIUM, LOW), CVE IDs, affected packages, and remediation guidance.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"accounts": map[string]interface{}{
						"type":        "array",
						"description": "AWS account IDs to query. Example: ['123456789012', '210987654321']",
						"items": map[string]interface{}{
							"type": "string",
						},
					},
					"regions": map[string]interface{}{
						"type":        "array",
						"description": "AWS regions to query ECR repositories. Defaults to ['us-east-1'] if not specified",
						"items": map[string]interface{}{
							"type": "string",
						},
					},
					"max_age_days": map[string]interface{}{
						"type":        "integer",
						"description": "Only include images pushed within the last N days. Default: 30",
					},
					"min_severity": map[string]interface{}{
						"type":        "string",
						"description": "Minimum severity to report (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL). Default: all severities",
						"enum":        []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"},
					},
					"repositories": map[string]interface{}{
						"type":        "array",
						"description": "Specific repository names to scan (optional, defaults to all repositories)",
						"items": map[string]interface{}{
							"type": "string",
						},
					},
				},
				"required": []string{"accounts"},
			},
		},
	}

	return result
}

// getToolDefinitions returns the list of available MCP tool definitions.
func getToolDefinitions() (result []MCPTool) {
	result = append(result, getLokiTools()...)
	result = append(result, getUtilityTools()...)
	result = append(result, getGitHubTools()...)
	result = append(result, getECRTools()...)

	return result
}

// handleListTools returns the list of available tools.
func (s *Server) handleListTools(_ context.Context, req MCPRequest) {
	tools := getToolDefinitions()

	response := MCPResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: map[string]interface{}{
			"tools": tools,
		},
	}

	data, _ := json.Marshal(response)
	fmt.Println(string(data))
}

// handleToolCall executes a tool and returns the result.
func (s *Server) handleToolCall(ctx context.Context, req MCPRequest) {
	var params MCPToolCallParams

	paramsJSON, _ := json.Marshal(req.Params)

	err := json.Unmarshal(paramsJSON, &params)
	if err != nil {
		s.sendError(req.ID, fmt.Sprintf("invalid params: %v", err))
		return
	}

	s.logger.InfoContext(ctx, "executing tool", slog.String("tool", params.Name))

	var result string

	switch params.Name {
	case "query_loki":
		result, err = s.executeQueryLoki(ctx, params.Arguments)

	case "whois_lookup":
		result, err = s.executeWhoisLookup(ctx, params.Arguments)

	case "generate_pdf":
		result, err = s.executeGeneratePDF(ctx, params.Arguments)

	case "github_get_file":
		result, err = s.executeGitHubGetFile(ctx, params.Arguments)

	case "github_list_directory":
		result, err = s.executeGitHubListDirectory(ctx, params.Arguments)

	case "github_search_code":
		result, err = s.executeGitHubSearchCode(ctx, params.Arguments)

	case "ecr_scan_results":
		result, err = s.executeECRScanResults(ctx, params.Arguments)

	default:
		s.sendError(req.ID, fmt.Sprintf("unknown tool: %s", params.Name))
		return
	}

	if err != nil {
		s.sendError(req.ID, fmt.Sprintf("tool execution error: %v", err))
		return
	}

	response := MCPResponse{
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

	data, _ := json.Marshal(response)
	fmt.Println(string(data))
}

// executeQueryLoki executes a Loki query.
func (s *Server) executeQueryLoki(ctx context.Context, args map[string]interface{}) (result string, err error) {
	var queryResult k8s.QueryResult

	query, _ := args["query"].(string)
	start, _ := args["start"].(string)
	end, _ := args["end"].(string)

	limit := 100
	if limitFloat, ok := args["limit"].(float64); ok {
		limit = int(limitFloat)
	}

	// Cap at 500 to avoid overwhelming Claude Code with data
	if limit > 500 {
		limit = 500
	}

	queryResult, err = s.lokiClient.Query(ctx, k8s.QueryRequest{
		Query: query,
		Start: start,
		End:   end,
		Limit: limit,
	})
	if err != nil {
		return result, err
	}

	result = queryResult.FormatResultAsText()
	return result, err
}

// executeWhoisLookup performs a whois lookup.
func (s *Server) executeWhoisLookup(ctx context.Context, args map[string]interface{}) (result string, err error) {
	var agent *k8s.Agent

	ipAddress, _ := args["ip_address"].(string)

	// Create a temporary k8s agent just for whois (doesn't need k8s client)
	agent, err = k8s.NewAgent("", s.logger)
	if err != nil {
		return result, err
	}

	result, err = agent.WhoisLookup(ctx, ipAddress)
	return result, err
}

// executeGeneratePDF generates a PDF from Markdown content using pandoc.
func (s *Server) executeGeneratePDF(ctx context.Context, args map[string]interface{}) (result string, err error) {
	markdownContent, _ := args["markdown_content"].(string)
	filename, _ := args["filename"].(string)
	title, _ := args["title"].(string)

	if markdownContent == "" {
		err = errors.New("markdown_content is required")
		return result, err
	}

	if filename == "" {
		err = errors.New("filename is required")
		return result, err
	}

	// Ensure .pdf extension
	if !strings.HasSuffix(filename, ".pdf") {
		filename += ".pdf"
	}

	// Create output path in /tmp
	outputPath := filepath.Join("/tmp", filename)

	// Write Markdown to temporary file
	tmpMD, mdErr := os.CreateTemp("/tmp", "report-*.md")
	if mdErr != nil {
		err = fmt.Errorf("creating temp Markdown file: %w", mdErr)
		return result, err
	}
	defer os.Remove(tmpMD.Name())

	_, writeErr := tmpMD.WriteString(markdownContent)
	if writeErr != nil {
		err = fmt.Errorf("writing Markdown content: %w", writeErr)
		return result, err
	}
	tmpMD.Close()

	// Convert Markdown to PDF using pandoc with company template
	var cmd *exec.Cmd
	cmdArgs := []string{
		"-f", "markdown",
		"-t", "pdf",
		"--pdf-engine=pdflatex",
		"--template=/app/latex-templates/company-template.latex",
		"--toc",
		"--number-sections",
		"--highlight-style=tango",
		"-o", outputPath,
	}

	// Add title if provided
	if title != "" {
		cmdArgs = append(cmdArgs, "-M", "title="+title)
	}

	// Add company name for branding
	cmdArgs = append(cmdArgs, "-M", "companyname="+s.companyName)

	cmdArgs = append(cmdArgs, tmpMD.Name())

	cmd = exec.CommandContext(ctx, "pandoc", cmdArgs...)

	// Set TEXINPUTS to include latex-templates directory so LaTeX can find company.cls
	// The trailing colon is important - it includes the default search paths
	cmd.Env = append(os.Environ(), "TEXINPUTS=.:/app/latex-templates//:")
	cmd.Dir = "/tmp" // Run from /tmp where output file is written

	var stderr bytes.Buffer
	var stdout bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout

	s.logger.InfoContext(ctx, "executing pandoc",
		slog.String("template", "/app/latex-templates/company-template.latex"),
		slog.String("company_name", s.companyName))

	execErr := cmd.Run()
	if execErr != nil {
		s.logger.ErrorContext(ctx, "pandoc execution failed",
			slog.String("error", execErr.Error()),
			slog.String("stderr", stderr.String()),
			slog.String("stdout", stdout.String()))
		err = fmt.Errorf("running pandoc: %w\nstderr: %s", execErr, stderr.String())
		return result, err
	}

	// Verify PDF was created
	stat, statErr := os.Stat(outputPath)
	if statErr != nil {
		err = fmt.Errorf("PDF not created: %w", statErr)
		return result, err
	}

	s.logger.InfoContext(ctx, "PDF generated successfully",
		slog.String("path", outputPath),
		slog.Int64("size_bytes", stat.Size()),
		slog.String("filename", filename))

	result = fmt.Sprintf("PDF generated successfully at %s (%.2f KB). The bot will automatically scan /tmp and upload this file to Slack.", outputPath, float64(stat.Size())/1024.0)
	return result, err
}

// executeGitHubGetFile fetches a file from a GitHub repository.
func (s *Server) executeGitHubGetFile(ctx context.Context, args map[string]interface{}) (result string, err error) {
	if s.githubClient == nil {
		err = errors.New("GitHub access not configured (GITHUB_TOKEN not set)")
		return result, err
	}

	owner, _ := args["owner"].(string)
	repo, _ := args["repo"].(string)
	path, _ := args["path"].(string)
	ref, _ := args["ref"].(string)

	if ref == "" {
		ref = "main"
	}

	opts := &github.RepositoryContentGetOptions{Ref: ref}
	fileContent, _, _, getErr := s.githubClient.Repositories.GetContents(ctx, owner, repo, path, opts)
	if getErr != nil {
		err = fmt.Errorf("fetching file from GitHub: %w", getErr)
		return result, err
	}

	if fileContent == nil {
		err = errors.New("file not found")
		return result, err
	}

	content, decodeErr := fileContent.GetContent()
	if decodeErr != nil {
		err = fmt.Errorf("decoding file content: %w", decodeErr)
		return result, err
	}

	s.logger.InfoContext(ctx, "fetched file from GitHub",
		slog.String("repo", fmt.Sprintf("%s/%s", owner, repo)),
		slog.String("path", path),
		slog.String("ref", ref),
		slog.Int("size", len(content)))

	result = fmt.Sprintf("File: %s/%s/%s (ref: %s)\nSize: %d bytes\n\n%s", owner, repo, path, ref, len(content), content)
	return result, err
}

// executeGitHubListDirectory lists files in a GitHub repository directory.
func (s *Server) executeGitHubListDirectory(ctx context.Context, args map[string]interface{}) (result string, err error) {
	if s.githubClient == nil {
		err = errors.New("GitHub access not configured (GITHUB_TOKEN not set)")
		return result, err
	}

	owner, _ := args["owner"].(string)
	repo, _ := args["repo"].(string)
	path, _ := args["path"].(string)
	ref, _ := args["ref"].(string)

	if ref == "" {
		ref = "main"
	}

	opts := &github.RepositoryContentGetOptions{Ref: ref}
	_, dirContents, _, listErr := s.githubClient.Repositories.GetContents(ctx, owner, repo, path, opts)
	if listErr != nil {
		err = fmt.Errorf("listing directory: %w", listErr)
		return result, err
	}

	var files []string

	for _, content := range dirContents {
		files = append(files, fmt.Sprintf("  %s  %-8s  %8d bytes",
			content.GetName(), content.GetType(), content.GetSize()))
	}

	s.logger.InfoContext(ctx, "listed directory from GitHub",
		slog.String("repo", fmt.Sprintf("%s/%s", owner, repo)),
		slog.String("path", path),
		slog.String("ref", ref),
		slog.Int("file_count", len(files)))

	result = fmt.Sprintf("Directory: %s/%s/%s (ref: %s)\nFiles: %d\n\n%s",
		owner, repo, path, ref, len(files), strings.Join(files, "\n"))
	return result, err
}

// executeGitHubSearchCode searches for code in GitHub repositories.
func (s *Server) executeGitHubSearchCode(ctx context.Context, args map[string]interface{}) (result string, err error) {
	if s.githubClient == nil {
		err = errors.New("GitHub access not configured (GITHUB_TOKEN not set)")
		return result, err
	}

	query, _ := args["query"].(string)

	opts := &github.SearchOptions{ListOptions: github.ListOptions{PerPage: 10}}
	searchResult, _, searchErr := s.githubClient.Search.Code(ctx, query, opts)
	if searchErr != nil {
		err = fmt.Errorf("searching code: %w", searchErr)
		return result, err
	}

	var results []string

	for _, codeResult := range searchResult.CodeResults {
		results = append(results, fmt.Sprintf("  %s:%s\n    URL: %s",
			codeResult.Repository.GetFullName(),
			codeResult.GetPath(),
			codeResult.GetHTMLURL()))
	}

	s.logger.InfoContext(ctx, "searched GitHub code",
		slog.String("query", query),
		slog.Int("total_count", searchResult.GetTotal()),
		slog.Int("returned", len(results)))

	result = fmt.Sprintf("Found %d results for: %s\n\n%s",
		searchResult.GetTotal(), query, strings.Join(results, "\n\n"))
	return result, err
}

// sendError sends an error response.
func (s *Server) sendError(id interface{}, message string) {
	response := MCPResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &MCPError{
			Code:    -32603,
			Message: message,
		},
	}

	data, _ := json.Marshal(response)
	fmt.Println(string(data))
}
