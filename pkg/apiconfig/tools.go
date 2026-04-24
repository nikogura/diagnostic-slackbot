package apiconfig

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
)

// MCPTool matches the MCP tool definition structure from pkg/mcp/types.go.
// Duplicated here to avoid circular imports.
type MCPTool struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// APIToolRegistry holds loaded API configs and their clients.
type APIToolRegistry struct {
	configs []*APIConfig
	clients map[string]*APIClient
	logger  *slog.Logger
}

// NewAPIToolRegistry creates a registry from loaded configs.
func NewAPIToolRegistry(configs []*APIConfig, logger *slog.Logger) (registry *APIToolRegistry) {
	clients := make(map[string]*APIClient, len(configs))

	for _, config := range configs {
		clients[config.Name] = NewAPIClient(config, logger)
	}

	registry = &APIToolRegistry{
		configs: configs,
		clients: clients,
		logger:  logger,
	}

	return registry
}

// GetToolDefinitions returns MCP tool definitions for all loaded API endpoints.
func (r *APIToolRegistry) GetToolDefinitions() (tools []MCPTool) {
	for _, config := range r.configs {
		for _, endpoint := range config.Endpoints {
			tool := buildToolDefinition(config, endpoint)
			tools = append(tools, tool)
		}
	}

	return tools
}

// DispatchToolCall routes a tool call to the correct API client and endpoint.
func (r *APIToolRegistry) DispatchToolCall(ctx context.Context, toolName string, args map[string]interface{}) (result string, handled bool, err error) {
	for _, config := range r.configs {
		prefix := config.Name + "_"
		if !strings.HasPrefix(toolName, prefix) {
			continue
		}

		endpointName := strings.TrimPrefix(toolName, prefix)
		client := r.clients[config.Name]

		result, err = client.Execute(ctx, endpointName, args)
		handled = true

		return result, handled, err
	}

	return result, handled, err
}

// HasTools returns true if any API tools are registered.
func (r *APIToolRegistry) HasTools() (has bool) {
	has = len(r.configs) > 0
	return has
}

// WriteToolUsage writes available API tool descriptions for the Claude prompt.
func (r *APIToolRegistry) WriteToolUsage(builder *strings.Builder) {
	for _, config := range r.configs {
		fmt.Fprintf(builder, "**%s API:**\n", config.Name)

		for _, endpoint := range config.Endpoints {
			toolName := config.Name + "_" + endpoint.Name
			desc := endpoint.Description
			if desc == "" {
				desc = endpoint.Name
			}

			fmt.Fprintf(builder, "- `%s`: %s\n", toolName, desc)
		}

		builder.WriteString("\n")
	}
}

func buildToolDefinition(config *APIConfig, endpoint Endpoint) (tool MCPTool) {
	toolName := config.Name + "_" + endpoint.Name

	description := endpoint.Description
	if description == "" {
		description = fmt.Sprintf("%s: %s %s", endpoint.Name, endpoint.Method, endpoint.Path)
	}

	properties := make(map[string]interface{})
	var required []string

	for _, param := range endpoint.Params {
		prop := map[string]interface{}{
			"type":        mapParamType(param.Type),
			"description": param.Description,
		}
		properties[param.Name] = prop

		if param.Required {
			required = append(required, param.Name)
		}
	}

	// Add common optional params
	properties["pretty"] = map[string]interface{}{
		"type":        "boolean",
		"description": "Pretty-print JSON response (default: false, saves tokens)",
	}

	schema := map[string]interface{}{
		"type":       "object",
		"properties": properties,
	}

	if len(required) > 0 {
		schema["required"] = required
	}

	tool = MCPTool{
		Name:        toolName,
		Description: description,
		InputSchema: schema,
	}

	return tool
}

func mapParamType(configType string) (jsonType string) {
	switch configType {
	case "integer":
		jsonType = "integer"
	case "boolean":
		jsonType = "boolean"
	case "number":
		jsonType = "number"
	default:
		jsonType = "string"
	}

	return jsonType
}
