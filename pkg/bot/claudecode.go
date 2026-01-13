package bot

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"github.com/nikogura/diagnostic-slackbot/pkg/investigations"
)

// ClaudeCodeRunner handles running Claude Code CLI for investigations.
type ClaudeCodeRunner struct {
	logger *slog.Logger
	model  string
}

// NewClaudeCodeRunner creates a new Claude Code runner.
func NewClaudeCodeRunner(model string, logger *slog.Logger) (result *ClaudeCodeRunner) {
	// Use default model if not specified
	if model == "" {
		model = "claude-sonnet-4-5-20250929"
	}

	result = &ClaudeCodeRunner{
		logger: logger,
		model:  model,
	}

	return result
}

// RunInvestigation runs Claude Code with the investigation template as the prompt.
func (r *ClaudeCodeRunner) RunInvestigation(ctx context.Context, template *investigations.InvestigationTemplate, userMessage string) (result string, err error) {
	// Build the prompt for Claude Code
	prompt := r.buildPrompt(template, userMessage)

	// Log investigation start with details
	r.logger.InfoContext(ctx, "starting Claude Code investigation",
		slog.String("template", template.Name),
		slog.String("user_message", userMessage),
		slog.Int("prompt_length", len(prompt)))

	cmd := exec.CommandContext(ctx, "claude",
		"--print",
		"--dangerously-skip-permissions",
		"--model", r.model,
		"--",
		prompt,
	)

	var stdout, stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Dir = "/app" // Set working directory to /app where .mcp.json is located
	cmd.Env = append(os.Environ(),
		"ANTHROPIC_API_KEY="+os.Getenv("ANTHROPIC_API_KEY"),
		"LOKI_ENDPOINT="+os.Getenv("LOKI_ENDPOINT"),
	)

	err = cmd.Run()

	// Always log stderr since Claude Code writes status messages there
	stderrStr := stderr.String()
	if stderrStr != "" {
		r.logger.InfoContext(ctx, "Claude Code stderr output",
			slog.String("stderr", stderrStr))
	}

	if err != nil {
		r.logger.ErrorContext(ctx, "Claude Code execution failed",
			slog.String("error", err.Error()),
			slog.String("stderr", stderrStr))

		err = fmt.Errorf("running Claude Code: %w\nstderr: %s", err, stderrStr)
		return result, err
	}

	result = stdout.String()

	// Log completion with response preview
	resultPreview := result
	if len(resultPreview) > 500 {
		resultPreview = result[:500] + "... (truncated)"
	}

	r.logger.InfoContext(ctx, "Claude Code investigation completed",
		slog.Int("output_bytes", len(result)),
		slog.String("output_preview", resultPreview))

	return result, err
}

// buildPrompt constructs the full prompt for Claude Code.
func (r *ClaudeCodeRunner) buildPrompt(template *investigations.InvestigationTemplate, userMessage string) (result string) {
	var builder strings.Builder

	// Investigation template prompt
	builder.WriteString("# Investigation Task\n\n")
	builder.WriteString(template.InitialPrompt)
	builder.WriteString("\n\n")

	// User's specific request
	builder.WriteString("# User Request\n\n")
	builder.WriteString(userMessage)
	builder.WriteString("\n\n")

	// Tool usage instructions
	builder.WriteString("# Available Tools\n\n")
	builder.WriteString("You have access to these MCP tools:\n\n")
	builder.WriteString("- **query_loki**: Query Loki for ModSecurity WAF logs. Use LogQL syntax.\n")
	builder.WriteString("  Example: `{realm=\"prod\", namespace=\"ingress-nginx\"} |~ \"ModSecurity\" | json | transaction_response_http_code=\"403\"`\n\n")
	builder.WriteString("- **whois_lookup**: Look up IP address geolocation, ISP, ASN.\n\n")
	builder.WriteString("Use these tools to gather data and perform your investigation. ")
	builder.WriteString("Start by querying Loki for relevant time periods, then analyze the results.\n\n")

	// Output format
	builder.WriteString("# Output Format\n\n")
	builder.WriteString("Provide your investigation findings in a clear, structured format:\n")
	builder.WriteString("1. Executive Summary (2-3 sentences)\n")
	builder.WriteString("2. Key Findings (bullet points)\n")
	builder.WriteString("3. Detailed Analysis\n")
	builder.WriteString("4. Recommendations\n\n")
	builder.WriteString("Be concise but thorough. Focus on actionable insights.\n\n")

	// PDF generation requirement
	builder.WriteString("# IMPORTANT: PDF Generation\n\n")
	builder.WriteString("**ALWAYS generate a PDF report** using the `generate_pdf` tool:\n\n")
	builder.WriteString("1. Write your complete report in Markdown format\n")
	builder.WriteString("2. Include all findings, analysis, tables (use Markdown table syntax)\n")
	builder.WriteString("3. Use Markdown formatting (# headers, ** bold, * lists, ``` code blocks, | tables)\n")
	builder.WriteString("4. Call generate_pdf with the Markdown content\n")
	builder.WriteString("5. Use descriptive filename (e.g., 'modsecurity_report_2025-01-10')\n")
	builder.WriteString("6. Include a title parameter for the PDF metadata\n\n")
	builder.WriteString("The PDF will be automatically uploaded to Slack for the user to download.\n")
	builder.WriteString("Do not just provide file paths - the PDF must be generated using the tool.\n")

	result = builder.String()
	return result
}
