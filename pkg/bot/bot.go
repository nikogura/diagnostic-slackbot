package bot

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nikogura/diagnostic-slackbot/pkg/investigations"
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/slackevents"
	"github.com/slack-go/slack/socketmode"
)

const (
	// ConversationExpiry is how long conversations remain active.
	ConversationExpiry = 24 * time.Hour

	// CleanupInterval is how often to cleanup expired conversations.
	CleanupInterval = 1 * time.Hour

	// DefaultFileRetention is how long to keep generated files before deletion.
	DefaultFileRetention = 24 * time.Hour
)

// Bot represents the Slack diagnostic bot.
type Bot struct {
	slackClient      *slack.Client
	socketClient     *socketmode.Client
	claudeCodeRunner *ClaudeCodeRunner
	skillLibrary     *investigations.SkillLibrary
	matcher          *investigations.Matcher
	conversations    *ConversationStore
	tracker          *InvestigationTracker
	logger           *slog.Logger
	botUserID        string
	fileRetention    time.Duration
}

// Config holds the bot configuration.
type Config struct {
	SlackBotToken    string
	SlackAppToken    string
	AnthropicAPIKey  string
	InvestigationDir string
	FileRetention    time.Duration // How long to keep generated files (0 = use default)
	GitHubToken      string        // GitHub personal access token for repository access
	ClaudeModel      string        // Claude model to use (e.g., "claude-sonnet-4-5-20250929")
}

// NewBot creates a new diagnostic bot.
func NewBot(cfg Config, logger *slog.Logger) (result *Bot, err error) {
	var skillLibrary *investigations.SkillLibrary
	var authResp *slack.AuthTestResponse

	// Load investigation skills
	skillLibrary, err = investigations.NewSkillLibrary(cfg.InvestigationDir)
	if err != nil {
		err = fmt.Errorf("loading investigation skills: %w", err)
		return result, err
	}

	matcher := investigations.NewMatcher(skillLibrary)

	// Initialize clients
	slackClient := slack.New(
		cfg.SlackBotToken,
		slack.OptionDebug(false),
		slack.OptionLog(slog.NewLogLogger(logger.Handler(), slog.LevelDebug)),
		slack.OptionAppLevelToken(cfg.SlackAppToken),
	)

	socketClient := socketmode.New(
		slackClient,
		socketmode.OptionDebug(false),
		socketmode.OptionLog(slog.NewLogLogger(logger.Handler(), slog.LevelDebug)),
	)

	// Create Claude Code runner
	claudeCodeRunner := NewClaudeCodeRunner(cfg.ClaudeModel, logger)

	// Get bot user ID
	authResp, err = slackClient.AuthTest()
	if err != nil {
		err = fmt.Errorf("authenticating with Slack: %w", err)
		return result, err
	}

	// Use configured retention or default
	fileRetention := cfg.FileRetention
	if fileRetention == 0 {
		fileRetention = DefaultFileRetention
	}

	result = &Bot{
		slackClient:      slackClient,
		socketClient:     socketClient,
		claudeCodeRunner: claudeCodeRunner,
		skillLibrary:     skillLibrary,
		matcher:          matcher,
		conversations:    NewConversationStore(ConversationExpiry),
		tracker:          NewInvestigationTracker(),
		logger:           logger,
		botUserID:        authResp.UserID,
		fileRetention:    fileRetention,
	}

	return result, err
}

// Start starts the bot and begins listening for events.
func (b *Bot) Start(ctx context.Context) (err error) {
	b.logger.InfoContext(ctx, "starting diagnostic bot",
		slog.String("bot_user_id", b.botUserID))

	// Start cleanup goroutine
	go b.cleanupLoop(ctx)

	// Handle socket mode events
	go b.handleSocketMode(ctx)

	// Run socket mode client
	err = b.socketClient.RunContext(ctx)
	if err != nil {
		err = fmt.Errorf("running socket mode client: %w", err)
		return err
	}

	return err
}

// handleSocketMode handles incoming socket mode events.
func (b *Bot) handleSocketMode(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return

		case evt := <-b.socketClient.Events:
			switch evt.Type { //nolint:exhaustive // Only handling core event types, others are ignored
			case socketmode.EventTypeEventsAPI:
				eventsAPI, ok := evt.Data.(slackevents.EventsAPIEvent)
				if !ok {
					b.logger.WarnContext(ctx, "failed to cast event to EventsAPIEvent")
					continue
				}

				b.socketClient.Ack(*evt.Request)
				go b.handleEventsAPI(ctx, eventsAPI)

			case socketmode.EventTypeInteractive:
				// Handle interactive events (buttons, etc.) if needed
				b.socketClient.Ack(*evt.Request)

			case socketmode.EventTypeSlashCommand:
				// Handle slash commands if needed
				b.socketClient.Ack(*evt.Request)

			default:
				// Ignore other event types (connection events, errors, etc.)
			}
		}
	}
}

// handleEventsAPI handles Events API events.
func (b *Bot) handleEventsAPI(ctx context.Context, event slackevents.EventsAPIEvent) {
	switch event.Type {
	case slackevents.CallbackEvent:
		innerEvent := event.InnerEvent

		switch ev := innerEvent.Data.(type) {
		case *slackevents.AppMentionEvent:
			b.handleAppMention(ctx, ev)

		case *slackevents.MessageEvent:
			b.handleMessage(ctx, ev)
		}
	}
}

// cleanupLoop periodically cleans up expired conversations and old files.
func (b *Bot) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			// Clean up expired conversations
			removed := b.conversations.CleanupExpired()
			if removed > 0 {
				b.logger.InfoContext(ctx, "cleaned up expired conversations",
					slog.Int("removed", removed))
			}

			// Clean up old generated files
			filesRemoved := b.cleanupOldFiles(ctx)
			if filesRemoved > 0 {
				b.logger.InfoContext(ctx, "cleaned up old files",
					slog.Int("removed", filesRemoved))
			}
		}
	}
}

// cleanupOldFiles removes PDF and markdown files older than fileRetention.
func (b *Bot) cleanupOldFiles(ctx context.Context) (result int) {
	searchDirs := []string{"/tmp", "/app/reports", "/app", "/home/bot"}
	patterns := []string{"*.pdf", "*.md"}
	cutoff := time.Now().Add(-b.fileRetention)

	for _, dir := range searchDirs {
		for _, pattern := range patterns {
			removed := b.cleanupFilesInDirectory(ctx, dir, pattern, cutoff)
			result += removed
		}
	}

	return result
}

// cleanupFilesInDirectory removes old files matching pattern in a directory.
func (b *Bot) cleanupFilesInDirectory(ctx context.Context, dir string, pattern string, cutoff time.Time) (result int) {
	matches, globErr := filepath.Glob(filepath.Join(dir, pattern))
	if globErr != nil {
		b.logger.WarnContext(ctx, "failed to glob files for cleanup",
			slog.String("dir", dir),
			slog.String("pattern", pattern),
			slog.String("error", globErr.Error()))
		return result
	}

	for _, filePath := range matches {
		removed := b.removeOldFile(ctx, filePath, cutoff)
		if removed {
			result++
		}
	}

	return result
}

// removeOldFile removes a single file if it's older than cutoff.
func (b *Bot) removeOldFile(ctx context.Context, filePath string, cutoff time.Time) (result bool) {
	fileInfo, statErr := os.Stat(filePath)
	if statErr != nil {
		b.logger.WarnContext(ctx, "failed to stat file for cleanup",
			slog.String("path", filePath),
			slog.String("error", statErr.Error()))
		return result
	}

	// Check if file is older than retention period
	if !fileInfo.ModTime().Before(cutoff) {
		return result
	}

	removeErr := os.Remove(filePath)
	if removeErr != nil {
		b.logger.WarnContext(ctx, "failed to remove old file",
			slog.String("path", filePath),
			slog.Time("mod_time", fileInfo.ModTime()),
			slog.String("error", removeErr.Error()))
		return result
	}

	b.logger.DebugContext(ctx, "removed old file",
		slog.String("path", filePath),
		slog.Time("mod_time", fileInfo.ModTime()),
		slog.Duration("age", time.Since(fileInfo.ModTime())))
	result = true

	return result
}

// stripMention removes bot mention from message text.
func (b *Bot) stripMention(text string) (result string) {
	result = strings.TrimSpace(strings.ReplaceAll(text, fmt.Sprintf("<@%s>", b.botUserID), ""))
	return result
}
