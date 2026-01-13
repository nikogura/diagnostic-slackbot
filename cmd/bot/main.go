package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nikogura/diagnostic-slackbot/pkg/bot"
	"github.com/nikogura/diagnostic-slackbot/pkg/metrics"
)

func main() {
	// Initialize structured logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	slog.SetDefault(logger)

	// Load configuration from environment
	cfg := bot.Config{
		SlackBotToken:    getEnv("SLACK_BOT_TOKEN", ""),
		SlackAppToken:    getEnv("SLACK_APP_TOKEN", ""),
		AnthropicAPIKey:  getEnv("ANTHROPIC_API_KEY", ""),
		InvestigationDir: getEnv("INVESTIGATION_DIR", "./investigations"),
		FileRetention:    parseFileRetention(logger),
		GitHubToken:      getEnv("GITHUB_TOKEN", ""),
		ClaudeModel:      getEnv("CLAUDE_MODEL", "claude-sonnet-4-5-20250929"),
	}

	// Validate required configuration
	if cfg.SlackBotToken == "" {
		logger.Warn("SLACK_BOT_TOKEN environment variable not set - Slack integration will not work")
	}

	if cfg.SlackAppToken == "" {
		logger.Warn("SLACK_APP_TOKEN environment variable not set - Slack integration will not work")
	}

	if cfg.AnthropicAPIKey == "" {
		logger.Warn("ANTHROPIC_API_KEY environment variable not set - Claude Code will not work")
	}

	logger.Info("starting Diagnostic Slackbot",
		slog.String("investigation_dir", cfg.InvestigationDir))

	// Create bot (will fail gracefully if Slack tokens missing)
	diagnosticBot, err := bot.NewBot(cfg, logger)
	if err != nil {
		logger.Warn("failed to create bot, continuing anyway for testing", slog.String("error", err.Error()))

		// Keep process alive for testing even if bot creation fails
		logger.Info("bot will not connect to Slack but container remains running for debugging")

		// Block forever with signal handling
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan
		logger.Info("received shutdown signal")
		return
	}

	// Setup signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start metrics server
	metricsServer := metrics.NewServer(":9090", logger)

	go func() {
		metricsErr := metricsServer.Start(ctx)
		if metricsErr != nil {
			logger.ErrorContext(ctx, "metrics server error", slog.String("error", metricsErr.Error()))
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start bot in goroutine
	errChan := make(chan error, 1)

	go func() {
		startErr := diagnosticBot.Start(ctx)
		if startErr != nil {
			errChan <- startErr
		}
	}()

	// Wait for shutdown signal or error
	select {
	case sig := <-sigChan:
		logger.Info("received shutdown signal", slog.String("signal", sig.String()))
		cancel()

	case botErr := <-errChan:
		logger.Error("bot encountered fatal error", slog.String("error", botErr.Error()))
		cancel()
		os.Exit(1)
	}

	logger.Info("bot shutdown complete")
}

// getEnv retrieves an environment variable with a default value.
func getEnv(key string, defaultValue string) (result string) {
	value := os.Getenv(key)
	if value == "" {
		result = defaultValue
		return result
	}

	result = value
	return result
}

// parseFileRetention parses the FILE_RETENTION environment variable.
// Returns 0 if not set or invalid (which triggers use of DefaultFileRetention).
func parseFileRetention(logger *slog.Logger) (result time.Duration) {
	retentionStr := os.Getenv("FILE_RETENTION")
	if retentionStr == "" {
		// Not set, use default (0 triggers DefaultFileRetention in NewBot)
		result = 0
		return result
	}

	var err error

	result, err = time.ParseDuration(retentionStr)
	if err != nil {
		logger.Warn("invalid FILE_RETENTION value, using default 24h",
			slog.String("value", retentionStr),
			slog.String("error", err.Error()))
		result = 0
		return result
	}

	if result <= 0 {
		logger.Warn("FILE_RETENTION must be positive, using default 24h",
			slog.Duration("value", result))
		result = 0
		return result
	}

	logger.Info("file retention configured",
		slog.Duration("retention", result))

	return result
}
