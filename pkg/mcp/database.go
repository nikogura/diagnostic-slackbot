package mcp

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql" // MySQL driver
	_ "github.com/lib/pq"              // PostgreSQL driver
	_ "github.com/mattn/go-sqlite3"    // SQLite driver
)

const (
	// Database driver names.
	postgresDriver = "postgres"
	mysqlDriver    = "mysql"
	sqliteDriver   = "sqlite3"

	// Environment variable prefixes.
	databaseEnvPrefix = "DATABASE_"
	databaseURLSuffix = "_URL"
)

// DatabaseClient handles read-only database queries.
type DatabaseClient struct {
	db     *sql.DB
	name   string
	logger *slog.Logger
}

// DatabaseClientConfig holds configuration for a database client.
type DatabaseClientConfig struct {
	Name     string
	URL      string
	Username string
	Password string
}

// DatabaseInfo contains metadata about a configured database.
type DatabaseInfo struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
}

// interpolateCredentials replaces credential placeholders in a connection string.
// Supported placeholders: {{USERNAME}}, {{PASSWORD}}, ${USERNAME}, ${PASSWORD}.
// If username and password are provided directly, they take precedence over environment variables.
func interpolateCredentials(connStr, username, password string, logger *slog.Logger) (result string) {
	result = connStr

	// Check for interpolation tokens and replace if credentials are available
	hasUsernameToken := strings.Contains(result, "{{USERNAME}}") || strings.Contains(result, "${USERNAME}")
	hasPasswordToken := strings.Contains(result, "{{PASSWORD}}") || strings.Contains(result, "${PASSWORD}")

	if hasUsernameToken && username != "" {
		result = strings.ReplaceAll(result, "{{USERNAME}}", username)
		result = strings.ReplaceAll(result, "${USERNAME}", username)
		logger.Debug("Interpolated username into connection string")
	}

	if hasPasswordToken && password != "" {
		result = strings.ReplaceAll(result, "{{PASSWORD}}", password)
		result = strings.ReplaceAll(result, "${PASSWORD}", password)
		logger.Debug("Interpolated password into connection string")
	}

	// Warn if tokens exist but credentials are missing
	if hasUsernameToken && username == "" {
		logger.Warn("Connection string contains username placeholder but no username provided")
	}
	if hasPasswordToken && password == "" {
		logger.Warn("Connection string contains password placeholder but no password provided")
	}

	return result
}

// NewDatabaseClient creates a new database client with read-only access.
// This is the legacy function that reads from DATABASE_URL environment variable.
// For multi-database support, use NewDatabaseClientWithConfig or LoadDatabaseClients.
func NewDatabaseClient(logger *slog.Logger) (result *DatabaseClient, err error) {
	// Get connection string from environment
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		// Try legacy environment variables
		connStr = os.Getenv("DB_CONNECTION_STRING")
	}

	if connStr == "" {
		err = errors.New("DATABASE_URL environment variable is required")
		return result, err
	}

	// Get credentials from legacy environment variables
	username := os.Getenv("DATABASE_USERNAME")
	password := os.Getenv("DATABASE_PASSWORD")

	config := DatabaseClientConfig{
		Name:     "default",
		URL:      connStr,
		Username: username,
		Password: password,
	}

	result, err = NewDatabaseClientWithConfig(config, logger)
	return result, err
}

// NewDatabaseClientWithConfig creates a new database client from explicit configuration.
func NewDatabaseClientWithConfig(config DatabaseClientConfig, logger *slog.Logger) (result *DatabaseClient, err error) {
	if config.URL == "" {
		err = fmt.Errorf("database URL is required for %q", config.Name)
		return result, err
	}

	// Interpolate credentials if placeholders exist
	connStr := interpolateCredentials(config.URL, config.Username, config.Password, logger)

	// Parse the connection string to determine the driver
	var driverName string
	driverName, connStr, err = parseConnectionString(connStr)
	if err != nil {
		return result, err
	}

	// Open database connection
	var db *sql.DB
	db, err = sql.Open(driverName, connStr)
	if err != nil {
		err = fmt.Errorf("failed to open database %q: %w", config.Name, err)
		return result, err
	}

	// Configure connection pool for read-only access
	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(2)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(1 * time.Minute)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = db.PingContext(ctx)
	if err != nil {
		err = fmt.Errorf("failed to ping database %q: %w", config.Name, err)
		_ = db.Close()
		return result, err
	}

	logger.Info("Database client initialized successfully", slog.String("name", config.Name))

	result = &DatabaseClient{
		db:     db,
		name:   config.Name,
		logger: logger,
	}

	return result, err
}

// parseConnectionString determines the driver and normalizes the connection string.
func parseConnectionString(connStr string) (driverName string, normalizedConnStr string, err error) {
	normalizedConnStr = connStr

	switch {
	case strings.HasPrefix(connStr, "postgres://") || strings.HasPrefix(connStr, "postgresql://"):
		driverName = postgresDriver
		// Convert URL format to lib/pq format if needed
		normalizedConnStr = strings.Replace(connStr, "postgresql://", "postgres://", 1)
	case strings.Contains(connStr, "host=") && strings.Contains(connStr, "dbname="):
		// Already in lib/pq format
		driverName = postgresDriver
	case strings.Contains(connStr, "user:pass@") && !strings.HasPrefix(connStr, "mysql://"):
		// Likely a postgres URL without scheme - common in legacy configs
		driverName = postgresDriver
		normalizedConnStr = "postgres://" + connStr
	case strings.HasPrefix(connStr, "mysql://"):
		driverName = mysqlDriver
		// Strip the mysql:// prefix for go-sql-driver/mysql
		normalizedConnStr = strings.TrimPrefix(connStr, "mysql://")
	case strings.HasPrefix(connStr, "sqlite3://") || strings.HasPrefix(connStr, "sqlite://"):
		driverName = sqliteDriver
		// Strip the prefix
		normalizedConnStr = strings.TrimPrefix(connStr, "sqlite3://")
		normalizedConnStr = strings.TrimPrefix(normalizedConnStr, "sqlite://")
	case strings.HasSuffix(connStr, ".db") || strings.HasSuffix(connStr, ".sqlite"):
		// Assume SQLite for .db or .sqlite files
		driverName = sqliteDriver
	default:
		err = errors.New("unsupported database connection string format (supports postgres://, mysql://, sqlite://)")
		return driverName, normalizedConnStr, err
	}

	return driverName, normalizedConnStr, err
}

// LoadDatabaseClients scans environment variables and creates database clients.
// It looks for patterns like DATABASE_<NAME>_URL where <NAME> is the database identifier.
// For each database, it also looks for DATABASE_<NAME>_USERNAME and DATABASE_<NAME>_PASSWORD.
// The legacy DATABASE_URL is loaded as the "default" database for backward compatibility.
func LoadDatabaseClients(logger *slog.Logger) (clients map[string]*DatabaseClient, err error) {
	clients = make(map[string]*DatabaseClient)

	// First, try to load the legacy DATABASE_URL as "default"
	legacyURL := os.Getenv("DATABASE_URL")
	if legacyURL == "" {
		legacyURL = os.Getenv("DB_CONNECTION_STRING")
	}

	if legacyURL != "" {
		config := DatabaseClientConfig{
			Name:     "default",
			URL:      legacyURL,
			Username: os.Getenv("DATABASE_USERNAME"),
			Password: os.Getenv("DATABASE_PASSWORD"),
		}

		var client *DatabaseClient
		client, err = NewDatabaseClientWithConfig(config, logger)
		if err != nil {
			logger.Warn("Failed to initialize default database",
				slog.String("error", err.Error()))
		} else {
			clients["default"] = client
		}
	}

	// Scan for DATABASE_<NAME>_URL patterns
	dbConfigs := scanDatabaseEnvVars(logger)

	for name, config := range dbConfigs {
		// Skip if we already loaded this as default
		if name == "default" {
			continue
		}

		var client *DatabaseClient
		client, err = NewDatabaseClientWithConfig(config, logger)
		if err != nil {
			logger.Warn("Failed to initialize database",
				slog.String("name", name),
				slog.String("error", err.Error()))
			continue
		}

		clients[name] = client
	}

	// Reset err since individual failures are logged but shouldn't fail the whole operation
	err = nil

	if len(clients) == 0 {
		logger.Info("No database clients configured")
	} else {
		logger.Info("Database clients loaded", slog.Int("count", len(clients)))
	}

	return clients, err
}

// scanDatabaseEnvVars scans environment variables for DATABASE_<NAME>_URL patterns.
func scanDatabaseEnvVars(logger *slog.Logger) (configs map[string]DatabaseClientConfig) {
	configs = make(map[string]DatabaseClientConfig)

	for _, env := range os.Environ() {
		// Split on first '=' to get key and value
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]

		// Check if this is a DATABASE_<NAME>_URL pattern
		if !strings.HasPrefix(key, databaseEnvPrefix) || !strings.HasSuffix(key, databaseURLSuffix) {
			continue
		}

		// Skip the legacy DATABASE_URL (handled separately)
		if key == "DATABASE_URL" {
			continue
		}

		// Extract the database name: DATABASE_<NAME>_URL -> <NAME>
		name := key[len(databaseEnvPrefix) : len(key)-len(databaseURLSuffix)]
		if name == "" {
			continue
		}

		// Normalize to lowercase for consistency
		name = strings.ToLower(name)

		// Get the URL value
		url := os.Getenv(key)
		if url == "" {
			continue
		}

		// Look for corresponding credentials
		// Try DATABASE_<NAME>_USERNAME first, fall back to DATABASE_USERNAME
		usernameKey := fmt.Sprintf("DATABASE_%s_USERNAME", strings.ToUpper(name))
		passwordKey := fmt.Sprintf("DATABASE_%s_PASSWORD", strings.ToUpper(name))

		username := os.Getenv(usernameKey)
		password := os.Getenv(passwordKey)

		logger.Debug("Found database configuration",
			slog.String("name", name),
			slog.String("url_key", key),
			slog.Bool("has_username", username != ""),
			slog.Bool("has_password", password != ""))

		configs[name] = DatabaseClientConfig{
			Name:     name,
			URL:      url,
			Username: username,
			Password: password,
		}
	}

	return configs
}

// GetAvailableDatabases returns information about all configured databases.
func GetAvailableDatabases(clients map[string]*DatabaseClient) (databases []DatabaseInfo) {
	databases = make([]DatabaseInfo, 0, len(clients))

	for name, client := range clients {
		databases = append(databases, DatabaseInfo{
			Name:      name,
			Available: client != nil && client.db != nil,
		})
	}

	return databases
}

// Close closes the database connection.
func (c *DatabaseClient) Close() (err error) {
	if c.db != nil {
		err = c.db.Close()
	}
	return err
}

// QueryResult represents the result of a database query.
type QueryResult struct {
	Columns  []string                 `json:"columns"`
	Rows     []map[string]interface{} `json:"rows"`
	RowCount int                      `json:"row_count"`
	Duration string                   `json:"duration,omitempty"`
	Error    string                   `json:"error,omitempty"`
}

// validateReadOnlyQuery checks if a query is safe to execute (read-only).
func validateReadOnlyQuery(query string) (err error) {
	upperQuery := strings.ToUpper(strings.TrimSpace(query))

	// Check for dangerous keywords as whole words (not part of column names)
	// Using word boundaries to avoid false positives
	forbidden := []string{
		"INSERT ", "UPDATE ", "DELETE ", "DROP ", "CREATE ",
		"ALTER ", "TRUNCATE ", "GRANT ", "REVOKE ", "EXEC ",
		"EXECUTE ", "CALL ", "MERGE ", "REPLACE ",
	}

	// Also check if query starts with these keywords
	forbiddenStarts := []string{
		"INSERT", "UPDATE", "DELETE", "DROP", "CREATE",
		"ALTER", "TRUNCATE", "GRANT", "REVOKE", "EXEC",
		"EXECUTE", "CALL", "MERGE", "REPLACE",
	}

	for _, keyword := range forbiddenStarts {
		if strings.HasPrefix(upperQuery, keyword) {
			err = fmt.Errorf("query contains forbidden keyword: %s", keyword)
			return err
		}
	}

	// Check for keywords followed by space in the middle of query
	// but exclude comments (basic comment detection)
	queryNoComments := upperQuery
	if idx := strings.Index(queryNoComments, "--"); idx != -1 {
		queryNoComments = queryNoComments[:idx]
	}
	if idx := strings.Index(queryNoComments, "/*"); idx != -1 {
		queryNoComments = queryNoComments[:idx]
	}

	for _, keyword := range forbidden {
		if strings.Contains(queryNoComments, " "+keyword) {
			err = fmt.Errorf("query contains forbidden keyword: %s", strings.TrimSpace(keyword))
			return err
		}
	}

	// Allow SELECT, WITH, SHOW, DESCRIBE, EXPLAIN
	validStarts := []string{"SELECT", "WITH", "SHOW", "DESCRIBE", "EXPLAIN"}
	isValid := false
	for _, start := range validStarts {
		if strings.HasPrefix(upperQuery, start) {
			isValid = true
			break
		}
	}

	if !isValid {
		err = errors.New("only SELECT, WITH, SHOW, DESCRIBE, and EXPLAIN queries are allowed")
		return err
	}

	return err
}

// ExecuteReadOnlyQuery executes a read-only SQL query.
func (c *DatabaseClient) ExecuteReadOnlyQuery(ctx context.Context, query string, args ...interface{}) (result QueryResult, err error) {
	startTime := time.Now()

	// Validate query is read-only
	err = validateReadOnlyQuery(query)
	if err != nil {
		result.Error = err.Error()
		return result, err
	}

	// Execute query with timeout
	queryCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var rows *sql.Rows
	rows, err = c.db.QueryContext(queryCtx, query, args...)
	if err != nil {
		c.logger.ErrorContext(ctx, "Database query failed",
			slog.String("query", query),
			slog.String("error", err.Error()),
			slog.Duration("duration", time.Since(startTime)),
		)
		result.Error = fmt.Sprintf("Query failed: %v", err)
		return result, err
	}
	defer rows.Close()

	// Get column names
	var columns []string
	columns, err = rows.Columns()
	if err != nil {
		result.Error = fmt.Sprintf("Failed to get columns: %v", err)
		return result, err
	}
	result.Columns = columns

	// Prepare scan targets
	values := make([]interface{}, len(columns))
	valuePtrs := make([]interface{}, len(columns))
	for i := range values {
		valuePtrs[i] = &values[i]
	}

	// Scan rows
	result.Rows = make([]map[string]interface{}, 0)
	rowCount := 0
	maxRows := 10000 // Hard limit

	for rows.Next() && rowCount < maxRows {
		err = rows.Scan(valuePtrs...)
		if err != nil {
			c.logger.WarnContext(ctx, "Failed to scan row",
				slog.String("error", err.Error()),
			)
			continue
		}

		// Build row map
		row := make(map[string]interface{})
		for i, col := range columns {
			val := values[i]
			// Convert byte arrays to strings
			if b, ok := val.([]byte); ok {
				val = string(b)
			}
			// Convert time.Time to RFC3339 string
			if t, ok := val.(time.Time); ok {
				val = t.Format(time.RFC3339)
			}
			row[col] = val
		}
		result.Rows = append(result.Rows, row)
		rowCount++
	}

	err = rows.Err()
	if err != nil {
		result.Error = fmt.Sprintf("Error iterating rows: %v", err)
		return result, err
	}

	result.RowCount = len(result.Rows)
	result.Duration = time.Since(startTime).String()

	c.logger.InfoContext(ctx, "Database query completed",
		slog.String("query", query),
		slog.Int("rows", result.RowCount),
		slog.Duration("duration", time.Since(startTime)),
	)

	return result, err
}
