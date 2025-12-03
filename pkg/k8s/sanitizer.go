package k8s

import (
	"regexp"
)

// Sanitizer removes sensitive data from logs before sending to Claude API.
type Sanitizer struct {
	patterns []*sensitizePattern
}

type sensitizePattern struct {
	regex       *regexp.Regexp
	replacement string
	description string
}

// NewSanitizer creates a new log sanitizer with predefined patterns.
func NewSanitizer() (result *Sanitizer) {
	patterns := []*sensitizePattern{
		// API Keys and tokens
		{
			regex:       regexp.MustCompile(`(?i)(api[_-]?key|apikey|api[_-]?token)\s*[=:]\s*["']?([A-Za-z0-9\-_]{20,})["']?`),
			replacement: `$1=***REDACTED***`,
			description: "API keys and tokens",
		},
		// Bearer tokens
		{
			regex:       regexp.MustCompile(`(?i)bearer\s+([A-Za-z0-9\-_\.]{20,})`),
			replacement: `Bearer ***REDACTED***`,
			description: "Bearer tokens",
		},
		// AWS credentials
		{
			regex:       regexp.MustCompile(`(?i)(aws[_-]?secret[_-]?access[_-]?key|aws[_-]?access[_-]?key[_-]?id)\s*[=:]\s*["']?([A-Za-z0-9/+=]{20,})["']?`),
			replacement: `$1=***REDACTED***`,
			description: "AWS credentials",
		},
		// Generic secrets
		{
			regex:       regexp.MustCompile(`(?i)(secret|password|passwd|pwd)[_-]?[a-z0-9]*\s*[=:]\s*["']?([^\s"']{8,})["']?`),
			replacement: `$1=***REDACTED***`,
			description: "Passwords and secrets",
		},
		// JWT tokens (more aggressive - match anything that looks like a JWT)
		{
			regex:       regexp.MustCompile(`eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+`),
			replacement: `***JWT_REDACTED***`,
			description: "JWT tokens",
		},
		// Base64 encoded data in headers/cookies (longer than 50 chars to avoid false positives)
		{
			regex:       regexp.MustCompile(`(?i)(authorization|cookie|x-auth[a-z\-]*)[:\s]+[A-Za-z0-9+/=]{50,}`),
			replacement: `$1: ***REDACTED***`,
			description: "Authorization headers",
		},
		// Credit card numbers (basic pattern)
		{
			regex:       regexp.MustCompile(`\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b`),
			replacement: `****-****-****-****`,
			description: "Credit card numbers",
		},
		// Email addresses (for PII protection)
		{
			regex:       regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b`),
			replacement: `***EMAIL_REDACTED***`,
			description: "Email addresses",
		},
		// IP addresses (if configured to redact)
		// Commented out by default - uncomment if IP redaction is required
		// {
		// 	regex:       regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`),
		// 	replacement: `***IP_REDACTED***`,
		// 	description: "IP addresses",
		// },
		// Private keys
		{
			regex:       regexp.MustCompile(`-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----[\s\S]+?-----END\s+(RSA\s+)?PRIVATE\s+KEY-----`),
			replacement: `***PRIVATE_KEY_REDACTED***`,
			description: "Private keys",
		},
		// Database connection strings
		{
			regex:       regexp.MustCompile(`(?i)(postgres|mysql|mongodb|redis)://[^:]+:[^@]+@[^\s]+`),
			replacement: `$1://***USERNAME***:***PASSWORD***@***HOST***`,
			description: "Database connection strings",
		},
		// Slack tokens
		{
			regex:       regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z\-]{10,}`),
			replacement: `***SLACK_TOKEN_REDACTED***`,
			description: "Slack tokens",
		},
		// GitHub tokens
		{
			regex:       regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`),
			replacement: `***GITHUB_TOKEN_REDACTED***`,
			description: "GitHub tokens",
		},
	}

	result = &Sanitizer{
		patterns: patterns,
	}

	return result
}

// Sanitize removes sensitive information from the input string.
func (s *Sanitizer) Sanitize(input string) (result string) {
	result = input

	for _, pattern := range s.patterns {
		result = pattern.regex.ReplaceAllString(result, pattern.replacement)
	}

	return result
}

// SanitizeWithReport sanitizes input and returns a report of what was redacted.
func (s *Sanitizer) SanitizeWithReport(input string) (sanitized string, redactionReport []string) {
	sanitized = input

	for _, pattern := range s.patterns {
		if pattern.regex.MatchString(sanitized) {
			redactionReport = append(redactionReport, pattern.description)
			sanitized = pattern.regex.ReplaceAllString(sanitized, pattern.replacement)
		}
	}

	return sanitized, redactionReport
}

// AddCustomPattern adds a custom sanitization pattern.
func (s *Sanitizer) AddCustomPattern(regex *regexp.Regexp, replacement string, description string) {
	s.patterns = append(s.patterns, &sensitizePattern{
		regex:       regex,
		replacement: replacement,
		description: description,
	})
}

// GetRedactionCount returns the number of redaction patterns configured.
func (s *Sanitizer) GetRedactionCount() (result int) {
	result = len(s.patterns)
	return result
}
