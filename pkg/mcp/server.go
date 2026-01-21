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

// MCP method constants.
const (
	methodInitialize = "initialize"
	methodToolsList  = "tools/list"
	methodToolsCall  = "tools/call"
)

// Tool name constants.
const (
	toolQueryLoki              = "query_loki"
	toolWhoisLookup            = "whois_lookup"
	toolGeneratePDF            = "generate_pdf"
	toolGitHubGetFile          = "github_get_file"
	toolGitHubListDirectory    = "github_list_directory"
	toolGitHubSearchCode       = "github_search_code"
	toolECRScanResults         = "ecr_scan_results"
	toolDatabaseQuery          = "database_query"
	toolGrafanaListDashboards  = "grafana_list_dashboards"
	toolGrafanaGetDashboard    = "grafana_get_dashboard"
	toolGrafanaCreateDashboard = "grafana_create_dashboard"
	toolGrafanaUpdateDashboard = "grafana_update_dashboard"
	toolGrafanaDeleteDashboard = "grafana_delete_dashboard"
)

// Server implements the MCP (Model Context Protocol) server.
type Server struct {
	lokiClient    *k8s.LokiClient
	githubClient  *github.Client
	dbClient      *DatabaseClient
	grafanaClient *GrafanaClient
	logger        *slog.Logger
	companyName   string
}

// NewServer creates a new MCP server.
func NewServer(lokiClient *k8s.LokiClient, githubToken string, logger *slog.Logger) (result *Server) {
	var githubClient *github.Client
	var dbClient *DatabaseClient
	var grafanaClient *GrafanaClient

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

	// Initialize database client if DATABASE_URL is provided
	if os.Getenv("DATABASE_URL") != "" {
		var err error
		dbClient, err = NewDatabaseClient(logger)
		if err != nil {
			logger.Warn("Database client initialization failed - database tools will be unavailable",
				slog.String("error", err.Error()))
		} else {
			logger.Info("Database client initialized - database tools available")
		}
	} else {
		logger.Info("DATABASE_URL not provided - database tools will be unavailable")
	}

	// Initialize Grafana client if configured
	grafanaURL := os.Getenv("GRAFANA_URL")
	grafanaAPIKey := os.Getenv("GRAFANA_API_KEY")
	if grafanaURL != "" && grafanaAPIKey != "" {
		var err error
		grafanaClient, err = NewGrafanaClient(grafanaURL, grafanaAPIKey, logger)
		if err != nil {
			logger.Warn("Grafana client initialization failed - Grafana tools will be unavailable",
				slog.String("error", err.Error()))
		} else {
			logger.Info("Grafana client initialized - Grafana dashboard tools available")
		}
	} else {
		logger.Info("GRAFANA_URL or GRAFANA_API_KEY not provided - Grafana tools will be unavailable")
	}

	// Get company name from environment, default to "Company"
	companyName := os.Getenv("COMPANY_NAME")
	if companyName == "" {
		companyName = "Company"
	}

	result = &Server{
		lokiClient:    lokiClient,
		githubClient:  githubClient,
		dbClient:      dbClient,
		grafanaClient: grafanaClient,
		logger:        logger,
		companyName:   companyName,
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
	case methodInitialize:
		s.handleInitialize(ctx, req)

	case methodToolsList:
		s.handleListTools(ctx, req)

	case methodToolsCall:
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
			Name:        toolQueryLoki,
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
			Name:        toolWhoisLookup,
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
			Name:        toolGeneratePDF,
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
			Name:        toolGitHubGetFile,
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
			Name:        toolGitHubListDirectory,
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
			Name:        toolGitHubSearchCode,
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
			Name:        toolECRScanResults,
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

// getDatabaseTools returns database-related tool definitions.
func getDatabaseTools() (result []MCPTool) {
	result = []MCPTool{
		{
			Name:        toolDatabaseQuery,
			Description: "Execute a read-only SQL query against a database. Supports PostgreSQL, MySQL, and SQLite. Only SELECT, WITH, SHOW, DESCRIBE, and EXPLAIN queries are allowed.",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]interface{}{
						"type":        "string",
						"description": "SQL query to execute (SELECT, WITH, SHOW, DESCRIBE, or EXPLAIN only)",
					},
				},
				"required": []string{"query"},
			},
		},
	}

	return result
}

// getGrafanaTools returns Grafana dashboard management tools.
func getGrafanaTools() (result []MCPTool) {
	result = append(result, getGrafanaReadTools()...)
	result = append(result, getGrafanaWriteTools()...)
	return result
}

// getGrafanaReadTools returns Grafana tools for reading/listing dashboards.
func getGrafanaReadTools() (result []MCPTool) {
	result = []MCPTool{
		{
			Name:        toolGrafanaListDashboards,
			Description: "List all Grafana dashboards the user has access to",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        toolGrafanaGetDashboard,
			Description: "Get a specific Grafana dashboard by UID",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"uid": map[string]interface{}{
						"type":        "string",
						"description": "Dashboard UID",
					},
				},
				"required": []string{"uid"},
			},
		},
	}
	return result
}

// getGrafanaWriteTools returns Grafana tools for creating/updating/deleting dashboards.
func getGrafanaWriteTools() (result []MCPTool) {
	result = append(result, getGrafanaCreateDashboardTool())
	result = append(result, getGrafanaModifyTools()...)
	return result
}

// getGrafanaCreateDashboardTool returns the tool definition for creating dashboards.
func getGrafanaCreateDashboardTool() (tool MCPTool) {
	tool = MCPTool{
		Name:        toolGrafanaCreateDashboard,
		Description: "Create a new Grafana dashboard from queries. Supports SQL (PostgreSQL/MySQL), Prometheus (PromQL), and CloudWatch metrics. Ideal for CEO-level business and operational metrics dashboards.",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"title": map[string]interface{}{
					"type":        "string",
					"description": "Dashboard title",
				},
				"panels": map[string]interface{}{
					"type":        "array",
					"description": "Array of panel configurations",
					"items": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"title": map[string]interface{}{
								"type":        "string",
								"description": "Panel title",
							},
							"query": map[string]interface{}{
								"type":        "string",
								"description": "Query for the panel (SQL, PromQL, or CloudWatch query)",
							},
							"sql": map[string]interface{}{
								"type":        "string",
								"description": "SQL query (deprecated, use 'query' instead)",
							},
							"panelType": map[string]interface{}{
								"type":        "string",
								"description": "Panel visualization type",
								"enum":        []string{"stat", "timeseries", "table", "piechart", "bargauge", "gauge", "heatmap"},
							},
							"datasourceType": map[string]interface{}{
								"type":        "string",
								"description": "Type of datasource (postgres, mysql, prometheus, cloudwatch)",
								"enum":        []string{"postgres", "mysql", "prometheus", "cloudwatch"},
								"default":     "postgres",
							},
							"datasourceUID": map[string]interface{}{
								"type":        "string",
								"description": "UID of the specific datasource",
								"default":     "postgres-main",
							},
							"description": map[string]interface{}{
								"type":        "string",
								"description": "Optional panel description",
							},
							"legend": map[string]interface{}{
								"type":        "string",
								"description": "Legend format for Prometheus queries (e.g., '{{instance}}')",
							},
							"region": map[string]interface{}{
								"type":        "string",
								"description": "AWS region for CloudWatch metrics (e.g., 'us-east-1')",
							},
							"namespace": map[string]interface{}{
								"type":        "string",
								"description": "CloudWatch namespace (e.g., 'AWS/EC2', 'AWS/RDS')",
							},
							"metricName": map[string]interface{}{
								"type":        "string",
								"description": "CloudWatch metric name (e.g., 'CPUUtilization')",
							},
							"statistics": map[string]interface{}{
								"type":        "array",
								"description": "CloudWatch statistics to fetch (e.g., ['Average', 'Maximum'])",
								"items": map[string]interface{}{
									"type": "string",
									"enum": []string{"Average", "Sum", "Maximum", "Minimum", "SampleCount"},
								},
							},
							"dimensions": map[string]interface{}{
								"type":        "object",
								"description": "CloudWatch dimensions as key-value pairs (e.g., {'InstanceId': 'i-123'})",
								"additionalProperties": map[string]interface{}{
									"type": "string",
								},
							},
						},
						"required": []string{"title", "panelType"},
					},
				},
			},
			"required": []string{"title", "panels"},
		},
	}
	return tool
}

// getGrafanaModifyTools returns Grafana tools for updating/deleting dashboards.
func getGrafanaModifyTools() (result []MCPTool) {
	result = []MCPTool{
		{
			Name:        toolGrafanaUpdateDashboard,
			Description: "Update an existing Grafana dashboard",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"uid": map[string]interface{}{
						"type":        "string",
						"description": "Dashboard UID to update",
					},
					"dashboard": map[string]interface{}{
						"type":        "object",
						"description": "Complete dashboard JSON object",
					},
					"message": map[string]interface{}{
						"type":        "string",
						"description": "Update message/reason",
					},
				},
				"required": []string{"uid", "dashboard"},
			},
		},
		{
			Name:        toolGrafanaDeleteDashboard,
			Description: "Delete a Grafana dashboard",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"uid": map[string]interface{}{
						"type":        "string",
						"description": "Dashboard UID to delete",
					},
				},
				"required": []string{"uid"},
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
	result = append(result, getDatabaseTools()...)
	result = append(result, getGrafanaTools()...)

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
	case toolQueryLoki:
		result, err = s.executeQueryLoki(ctx, params.Arguments)

	case toolWhoisLookup:
		result, err = s.executeWhoisLookup(ctx, params.Arguments)

	case toolGeneratePDF:
		result, err = s.executeGeneratePDF(ctx, params.Arguments)

	case toolGitHubGetFile:
		result, err = s.executeGitHubGetFile(ctx, params.Arguments)

	case toolGitHubListDirectory:
		result, err = s.executeGitHubListDirectory(ctx, params.Arguments)

	case toolGitHubSearchCode:
		result, err = s.executeGitHubSearchCode(ctx, params.Arguments)

	case toolECRScanResults:
		result, err = s.executeECRScanResults(ctx, params.Arguments)

	case toolDatabaseQuery:
		result, err = s.executeDatabaseQuery(ctx, params.Arguments)

	case toolGrafanaListDashboards:
		result, err = s.executeGrafanaListDashboards(ctx, params.Arguments)

	case toolGrafanaGetDashboard:
		result, err = s.executeGrafanaGetDashboard(ctx, params.Arguments)

	case toolGrafanaCreateDashboard:
		result, err = s.executeGrafanaCreateDashboard(ctx, params.Arguments)

	case toolGrafanaUpdateDashboard:
		result, err = s.executeGrafanaUpdateDashboard(ctx, params.Arguments)

	case toolGrafanaDeleteDashboard:
		result, err = s.executeGrafanaDeleteDashboard(ctx, params.Arguments)

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

// executeDatabaseQuery executes a read-only database query.
func (s *Server) executeDatabaseQuery(ctx context.Context, args map[string]interface{}) (result string, err error) {
	if s.dbClient == nil {
		err = errors.New("database access not configured (DATABASE_URL not set)")
		return result, err
	}

	query, _ := args["query"].(string)
	if query == "" {
		err = errors.New("query parameter is required")
		return result, err
	}

	// Execute the read-only query
	var queryResult QueryResult
	queryResult, err = s.dbClient.ExecuteReadOnlyQuery(ctx, query)
	if err != nil {
		return result, err
	}

	// Format the result as JSON for Claude to parse
	var resultBytes []byte
	resultBytes, err = json.MarshalIndent(queryResult, "", "  ")
	if err != nil {
		err = fmt.Errorf("formatting query result: %w", err)
		return result, err
	}

	result = string(resultBytes)
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

// executeGrafanaListDashboards lists all Grafana dashboards.
func (s *Server) executeGrafanaListDashboards(ctx context.Context, _ map[string]interface{}) (result string, err error) {
	if s.grafanaClient == nil {
		err = errors.New("grafana access not configured (GRAFANA_URL or GRAFANA_API_KEY not set)")
		return result, err
	}

	var dashboards []DashboardSearchResponse
	dashboards, err = s.grafanaClient.ListDashboards(ctx)
	if err != nil {
		return result, err
	}

	// Format the result as JSON
	var resultBytes []byte
	resultBytes, err = json.MarshalIndent(dashboards, "", "  ")
	if err != nil {
		err = fmt.Errorf("formatting dashboard list: %w", err)
		return result, err
	}

	result = string(resultBytes)
	return result, err
}

// executeGrafanaGetDashboard retrieves a specific dashboard.
func (s *Server) executeGrafanaGetDashboard(ctx context.Context, args map[string]interface{}) (result string, err error) {
	if s.grafanaClient == nil {
		err = errors.New("grafana access not configured (GRAFANA_URL or GRAFANA_API_KEY not set)")
		return result, err
	}

	uid, _ := args["uid"].(string)
	if uid == "" {
		err = errors.New("uid parameter is required")
		return result, err
	}

	var dashboard *Dashboard
	dashboard, err = s.grafanaClient.GetDashboard(ctx, uid)
	if err != nil {
		return result, err
	}

	// Format the result as JSON
	var resultBytes []byte
	resultBytes, err = json.MarshalIndent(dashboard, "", "  ")
	if err != nil {
		err = fmt.Errorf("formatting dashboard: %w", err)
		return result, err
	}

	result = string(resultBytes)
	return result, err
}

// parsePanelConfigs parses raw panel data into PanelQueryConfig structs.
func (s *Server) parsePanelConfigs(panelsRaw []interface{}) (panels []PanelQueryConfig, err error) {
	for _, panelRaw := range panelsRaw {
		panelMap, panelOk := panelRaw.(map[string]interface{})
		if !panelOk {
			err = errors.New("each panel must be an object")
			return panels, err
		}

		panel := s.parseSinglePanelConfig(panelMap)
		panels = append(panels, panel)
	}
	return panels, err
}

// parseSinglePanelConfig parses a single panel configuration.
func (s *Server) parseSinglePanelConfig(panelMap map[string]interface{}) (panel PanelQueryConfig) {
	panel.Title, _ = panelMap["title"].(string)
	panel.PanelType, _ = panelMap["panelType"].(string)
	panel.DatasourceUID, _ = panelMap["datasourceUID"].(string)

	// Support both 'query' and 'sql' fields for backward compatibility
	panel.Query, _ = panelMap["query"].(string)
	if panel.Query == "" {
		panel.Query, _ = panelMap["sql"].(string) // Fallback to old field
	}

	// Determine datasource type (default to postgres for backward compatibility)
	panel.DatasourceType, _ = panelMap["datasourceType"].(string)
	if panel.DatasourceType == "" && panel.Query != "" {
		panel.DatasourceType = "postgres" // Default for backward compatibility
	}

	// Parse optional fields for different datasource types
	panel.Legend, _ = panelMap["legend"].(string)
	panel.Region, _ = panelMap["region"].(string)
	panel.Namespace, _ = panelMap["namespace"].(string)
	panel.MetricName, _ = panelMap["metricName"].(string)

	// Parse statistics array for CloudWatch
	if statsRaw, statsOk := panelMap["statistics"].([]interface{}); statsOk {
		for _, stat := range statsRaw {
			if statStr, statOk := stat.(string); statOk {
				panel.Statistics = append(panel.Statistics, statStr)
			}
		}
	}

	// Parse dimensions map for CloudWatch
	panel.Dimensions = make(map[string]string)
	if dimRaw, dimOk := panelMap["dimensions"].(map[string]interface{}); dimOk {
		for k, v := range dimRaw {
			if vStr, vOk := v.(string); vOk {
				panel.Dimensions[k] = vStr
			}
		}
	}

	return panel
}

// executeGrafanaCreateDashboard creates a new dashboard from queries (SQL, PromQL, CloudWatch).
func (s *Server) executeGrafanaCreateDashboard(ctx context.Context, args map[string]interface{}) (result string, err error) {
	if s.grafanaClient == nil {
		err = errors.New("grafana access not configured (GRAFANA_URL or GRAFANA_API_KEY not set)")
		return result, err
	}

	title, _ := args["title"].(string)
	if title == "" {
		err = errors.New("title parameter is required")
		return result, err
	}

	// Parse panels array
	panelsRaw, ok := args["panels"].([]interface{})
	if !ok || len(panelsRaw) == 0 {
		err = errors.New("panels parameter is required and must be a non-empty array")
		return result, err
	}

	// Parse panels into PanelQueryConfig for multi-datasource support
	var panels []PanelQueryConfig
	panels, err = s.parsePanelConfigs(panelsRaw)
	if err != nil {
		return result, err
	}

	// Create the dashboard with multi-datasource support
	var uid string
	uid, err = s.grafanaClient.CreateDashboardFromQueries(ctx, title, panels)
	if err != nil {
		return result, err
	}

	result = fmt.Sprintf("Successfully created dashboard '%s' with UID: %s\n\nDashboard URL: %s/d/%s/%s",
		title, uid, s.grafanaClient.baseURL, uid, strings.ReplaceAll(strings.ToLower(title), " ", "-"))
	return result, err
}

// executeGrafanaUpdateDashboard updates an existing dashboard.
func (s *Server) executeGrafanaUpdateDashboard(ctx context.Context, args map[string]interface{}) (result string, err error) {
	if s.grafanaClient == nil {
		err = errors.New("grafana access not configured (GRAFANA_URL or GRAFANA_API_KEY not set)")
		return result, err
	}

	uid, _ := args["uid"].(string)
	if uid == "" {
		err = errors.New("uid parameter is required")
		return result, err
	}

	dashboardRaw, ok := args["dashboard"].(map[string]interface{})
	if !ok {
		err = errors.New("dashboard parameter is required and must be an object")
		return result, err
	}

	message, _ := args["message"].(string)
	if message == "" {
		message = "Updated via MCP"
	}

	// Convert the dashboard map to Dashboard struct
	var dashboardBytes []byte
	dashboardBytes, err = json.Marshal(dashboardRaw)
	if err != nil {
		err = fmt.Errorf("marshaling dashboard: %w", err)
		return result, err
	}

	var dashboard Dashboard
	err = json.Unmarshal(dashboardBytes, &dashboard)
	if err != nil {
		err = fmt.Errorf("unmarshaling dashboard: %w", err)
		return result, err
	}

	dashboard.UID = uid

	err = s.grafanaClient.UpdateDashboard(ctx, &dashboard, message)
	if err != nil {
		return result, err
	}

	result = fmt.Sprintf("Successfully updated dashboard with UID: %s", uid)
	return result, err
}

// executeGrafanaDeleteDashboard deletes a dashboard.
func (s *Server) executeGrafanaDeleteDashboard(ctx context.Context, args map[string]interface{}) (result string, err error) {
	if s.grafanaClient == nil {
		err = errors.New("grafana access not configured (GRAFANA_URL or GRAFANA_API_KEY not set)")
		return result, err
	}

	uid, _ := args["uid"].(string)
	if uid == "" {
		err = errors.New("uid parameter is required")
		return result, err
	}

	err = s.grafanaClient.DeleteDashboard(ctx, uid)
	if err != nil {
		return result, err
	}

	result = fmt.Sprintf("Successfully deleted dashboard with UID: %s", uid)
	return result, err
}
