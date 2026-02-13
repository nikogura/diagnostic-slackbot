package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nikogura/diagnostic-slackbot/pkg/bot"
	"github.com/nikogura/diagnostic-slackbot/pkg/k8s"
	"github.com/nikogura/diagnostic-slackbot/pkg/mcp"
	"github.com/nikogura/diagnostic-slackbot/pkg/mcp/auth"
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

	// Start MCP HTTP server if enabled
	startMCPHTTPServer(ctx, cfg.GitHubToken, logger)

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

// startMCPHTTPServer starts the MCP HTTP server if MCP_HTTP_ENABLED is true.
func startMCPHTTPServer(ctx context.Context, githubToken string, logger *slog.Logger) {
	mcpHTTPEnabled := getEnv("MCP_HTTP_ENABLED", "false")
	//nolint:goconst // "true" is a common boolean string, not worth a constant
	if mcpHTTPEnabled != "true" {
		return
	}

	mcpHTTPPort := getEnv("MCP_HTTP_PORT", "8090")
	mcpHTTPAddr := ":" + mcpHTTPPort

	lokiEndpoint := getEnv("LOKI_ENDPOINT", "")
	if lokiEndpoint == "" {
		logger.WarnContext(ctx, "LOKI_ENDPOINT not set - MCP Loki tools will be unavailable")
		lokiEndpoint = "http://localhost:3100" // Fallback
	}

	lokiClient := k8s.NewLokiClient(lokiEndpoint, logger)
	mcpServer := mcp.NewServer(lokiClient, githubToken, logger)

	// Build authentication chain from environment variables
	authChain := buildAuthChain(logger)

	go func() {
		if authChain == nil {
			logger.InfoContext(ctx, "starting MCP HTTP server without authentication", slog.String("addr", mcpHTTPAddr))
		} else {
			logger.InfoContext(ctx, "starting MCP HTTP server with authentication enabled", slog.String("addr", mcpHTTPAddr))
		}
		mcpErr := mcpServer.RunHTTP(ctx, mcpHTTPAddr, authChain)
		if mcpErr != nil {
			logger.ErrorContext(ctx, "MCP HTTP server error", slog.String("error", mcpErr.Error()))
		}
	}()
}

// buildAuthChain builds an authentication chain from environment variables.
// Returns nil if no auth methods are configured (auth disabled).
//
//nolint:gocognit // Multiple auth methods require branching logic
func buildAuthChain(logger *slog.Logger) (chain *auth.Chain) {
	var methods []auth.Method

	// 1. Static Bearer Token Auth
	if token := getEnv("MCP_AUTH_TOKEN", ""); token != "" {
		methods = append(methods, auth.NewStaticTokenAuth(token))
		logger.Info("configured static bearer token authentication")
	}

	// 2. JWT Auth
	if secret := getEnv("MCP_JWT_SECRET", ""); secret != "" {
		algorithm := getEnv("MCP_JWT_ALGORITHM", "HS256")
		jwtAuth, err := auth.NewJWTAuth(&auth.JWTConfig{
			Secret:    []byte(secret),
			Algorithm: algorithm,
		})
		if err != nil {
			logger.Warn("failed to configure JWT auth", slog.String("error", err.Error()))
		} else {
			methods = append(methods, jwtAuth)
			logger.Info("configured JWT authentication", slog.String("algorithm", algorithm))
		}
	}

	// 3. API Key Auth
	if apiKeysStr := getEnv("MCP_API_KEYS", ""); apiKeysStr != "" {
		// Format: "key1:user1,key2:user2"
		keys := make(map[string]string)
		for _, pair := range strings.Split(apiKeysStr, ",") {
			parts := strings.SplitN(strings.TrimSpace(pair), ":", 2)
			if len(parts) == 2 {
				keys[parts[0]] = parts[1]
			}
		}
		if len(keys) > 0 {
			methods = append(methods, auth.NewAPIKeyAuth(keys))
			logger.Info("configured API key authentication", slog.Int("keys_count", len(keys)))
		}
	}

	// 4. OIDC Auth
	if issuerURL := getEnv("MCP_OIDC_ISSUER_URL", ""); issuerURL != "" {
		audience := getEnv("MCP_OIDC_AUDIENCE", "")
		allowedGroupsStr := getEnv("MCP_OIDC_ALLOWED_GROUPS", "")
		skipIssuerVerify := getEnv("MCP_OIDC_SKIP_ISSUER_VERIFY", "false") == "true"

		var allowedGroups []string
		if allowedGroupsStr != "" {
			allowedGroups = strings.Split(allowedGroupsStr, ",")
			for i := range allowedGroups {
				allowedGroups[i] = strings.TrimSpace(allowedGroups[i])
			}
		}

		oidcAuth := auth.NewOIDCAuth(&auth.OIDCConfig{
			IssuerURL:        issuerURL,
			Audience:         audience,
			AllowedGroups:    allowedGroups,
			SkipIssuerVerify: skipIssuerVerify,
		}, logger)
		methods = append(methods, oidcAuth)
		logger.Info("configured OIDC authentication",
			slog.String("issuer_url", issuerURL),
			slog.String("audience", audience),
			slog.Any("allowed_groups", allowedGroups))
	}

	// 5. mTLS Auth
	if caCertPath := getEnv("MCP_MTLS_CA_CERT_PATH", ""); caCertPath != "" {
		verifyClient := getEnv("MCP_MTLS_VERIFY_CLIENT", "true") == "true"
		mtlsAuth, err := auth.NewMTLSAuth(&auth.MTLSConfig{
			CACertPath:   caCertPath,
			VerifyClient: verifyClient,
		})
		if err != nil {
			logger.Warn("failed to configure mTLS auth", slog.String("error", err.Error()))
		} else {
			methods = append(methods, mtlsAuth)
			logger.Info("configured mTLS authentication",
				slog.String("ca_cert_path", caCertPath),
				slog.Bool("verify_client", verifyClient))
		}
	}

	// Return nil if no methods configured (auth disabled)
	if len(methods) == 0 {
		return chain
	}

	chain = auth.NewChain(methods, logger)
	return chain
}
