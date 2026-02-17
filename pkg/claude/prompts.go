package claude

import (
	"fmt"
	"strings"

	"github.com/nikogura/diagnostic-slackbot/pkg/investigations"
)

// BuildSystemPrompt constructs the system prompt for Claude including the investigation
// skill, engineering standards, and context documents.
func BuildSystemPrompt(skill *investigations.InvestigationSkill, engineeringStandards string, contextDocs map[string]string) (result string) {
	var builder strings.Builder

	// Investigation-specific prompt
	builder.WriteString(skill.InitialPrompt)
	builder.WriteString("\n\n")

	// Engineering standards
	if engineeringStandards != "" {
		builder.WriteString("# Engineering Standards\n\n")
		builder.WriteString(engineeringStandards)
		builder.WriteString("\n\n")
	}

	// Context documents
	if len(contextDocs) > 0 {
		builder.WriteString("# Reference Documentation\n\n")

		for docName, docContent := range contextDocs {
			fmt.Fprintf(&builder, "## %s\n\n", docName)
			builder.WriteString(docContent)
			builder.WriteString("\n\n")
		}
	}

	// Tool usage reminder
	writeToolUsage(&builder)

	// Security reminder
	builder.WriteString("# Security Reminder\n\n")
	builder.WriteString("- This is a production cryptocurrency trading platform\n")
	builder.WriteString("- All queries are logged and auditable\n")
	builder.WriteString("- You have READ-ONLY access - never suggest write operations\n")
	builder.WriteString("- Be mindful of PII and sensitive data in your responses\n")
	builder.WriteString("- Follow GitOps principles - all changes must go through git\n")

	result = builder.String()
	return result
}

// FormatInitialContext formats the initial Kubernetes resources fetched for an investigation.
func FormatInitialContext(resources map[string]string) (result string) {
	if len(resources) == 0 {
		result = "No initial Kubernetes resources were fetched."
		return result
	}

	var builder strings.Builder

	builder.WriteString("# Initial Kubernetes Context\n\n")
	builder.WriteString("The following resources have been fetched to assist with your investigation:\n\n")

	for resourceName, resourceData := range resources {
		fmt.Fprintf(&builder, "## %s\n\n", resourceName)
		builder.WriteString("```\n")
		builder.WriteString(resourceData)
		builder.WriteString("\n```\n\n")
	}

	result = builder.String()
	return result
}

// FormatToolResult formats the result of a tool execution for Claude.
func FormatToolResult(toolName string, result string, err error) (formatted string, isError bool) {
	const maxResultBytes = 50000 // ~15k tokens max per tool result

	if err != nil {
		formatted = fmt.Sprintf("Error executing %s: %v", toolName, err)
		isError = true

		return formatted, isError
	}

	// Truncate large results to prevent token overflow
	if len(result) > maxResultBytes {
		formatted = result[:maxResultBytes] + fmt.Sprintf("\n\n... (truncated %d bytes to fit context window)", len(result)-maxResultBytes)
	} else {
		formatted = result
	}

	isError = false

	return formatted, isError
}

// writeToolUsage writes the tool usage section of the system prompt.
func writeToolUsage(builder *strings.Builder) {
	builder.WriteString("# Tool Usage\n\n")
	builder.WriteString("You have access to the following tools to gather information:\n\n")
	builder.WriteString("**Logging & Observability:**\n")
	builder.WriteString("- `query_loki`: Query Loki for cluster logs (ModSecurity, application logs)\n")
	builder.WriteString("- `cloudwatch_logs_query`: Execute CloudWatch Logs Insights queries across AWS log groups\n")
	builder.WriteString("- `cloudwatch_logs_list_groups`: List available CloudWatch log groups in an AWS region\n")
	builder.WriteString("- `cloudwatch_logs_get_events`: Get log events from a specific CloudWatch log stream\n")
	builder.WriteString("- `prometheus_query`: Execute an instant PromQL query\n")
	builder.WriteString("- `prometheus_query_range`: Execute a range PromQL query for trend analysis\n")
	builder.WriteString("- `prometheus_series`: Find time series matching label selectors\n")
	builder.WriteString("- `prometheus_label_values`: Get all values for a given label name\n")
	builder.WriteString("- `prometheus_list_endpoints`: List configured Prometheus endpoints\n\n")
	builder.WriteString("**Kubernetes:**\n")
	builder.WriteString("- `get_k8s_pod_logs`: Fetch pod logs from Kubernetes\n")
	builder.WriteString("- `get_k8s_resource`: Get K8s resource configs (ConfigMap, Deployment, etc.)\n")
	builder.WriteString("- `list_k8s_pods`: List pods in a namespace\n")
	builder.WriteString("- `get_k8s_events`: Get K8s events for troubleshooting\n\n")
	builder.WriteString("**Security & Infrastructure:**\n")
	builder.WriteString("- `whois_lookup`: Look up IP address geolocation and ISP\n")
	builder.WriteString("- `ecr_scan_results`: Query AWS ECR for container image vulnerability scan results\n\n")
	builder.WriteString("**Grafana:**\n")
	builder.WriteString("- `grafana_list_dashboards`: List all Grafana dashboards\n")
	builder.WriteString("- `grafana_get_dashboard`: Get a specific Grafana dashboard by UID\n")
	builder.WriteString("- `grafana_create_dashboard`: Create a new Grafana dashboard\n")
	builder.WriteString("- `grafana_update_dashboard`: Update an existing Grafana dashboard\n")
	builder.WriteString("- `grafana_delete_dashboard`: Delete a Grafana dashboard\n\n")
	builder.WriteString("**Data & Code:**\n")
	builder.WriteString("- `database_query`: Execute read-only SQL queries (SELECT, SHOW, DESCRIBE, EXPLAIN)\n")
	builder.WriteString("- `database_list`: List available databases\n")
	builder.WriteString("- `github_get_file`: Fetch a file from a GitHub repository\n")
	builder.WriteString("- `github_list_directory`: List files in a GitHub repository directory\n")
	builder.WriteString("- `github_search_code`: Search for code across GitHub repositories\n\n")
	builder.WriteString("**Reporting:**\n")
	builder.WriteString("- `generate_pdf`: Generate a PDF report from Markdown content\n\n")
	builder.WriteString("Use these tools to gather the information you need to complete your investigation. ")
	builder.WriteString("You can call multiple tools in sequence to build a complete picture. ")
	builder.WriteString("Use the tool that matches what the user is asking about - if they ask about CloudWatch, use CloudWatch tools; if they ask about cluster logs, use Loki.\n\n")
}
