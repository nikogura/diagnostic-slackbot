package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/nikogura/diagnostic-slackbot/pkg/k8s"
	"github.com/nikogura/diagnostic-slackbot/pkg/mcp"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Get configuration from environment
	lokiEndpoint := os.Getenv("LOKI_ENDPOINT")
	if lokiEndpoint == "" {
		logger.Error("LOKI_ENDPOINT environment variable not set")
		os.Exit(1)
	}

	githubToken := os.Getenv("GITHUB_TOKEN")
	if githubToken == "" {
		logger.Warn("GITHUB_TOKEN not set - GitHub tools will be unavailable")
	}

	// Initialize clients
	lokiClient := k8s.NewLokiClient(lokiEndpoint, logger)

	// Create MCP server
	server := mcp.NewServer(lokiClient, githubToken, logger)

	// Run server (stdio transport)
	ctx := context.Background()

	err := server.Run(ctx)
	if err != nil {
		logger.Error("MCP server error", slog.String("error", err.Error()))
		os.Exit(1)
	}
}
