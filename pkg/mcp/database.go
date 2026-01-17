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
)

// DatabaseClient handles read-only database queries.
type DatabaseClient struct {
	db     *sql.DB
	logger *slog.Logger
}

// NewDatabaseClient creates a new database client with read-only access.
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

	// Parse the connection string to determine the driver
	var driverName string
	switch {
	case strings.HasPrefix(connStr, "postgres://") || strings.HasPrefix(connStr, "postgresql://"):
		driverName = postgresDriver
		// Convert URL format to lib/pq format if needed
		connStr = strings.Replace(connStr, "postgresql://", "postgres://", 1)
	case strings.Contains(connStr, "host=") && strings.Contains(connStr, "dbname="):
		// Already in lib/pq format
		driverName = postgresDriver
	case strings.Contains(connStr, "user:pass@") && !strings.HasPrefix(connStr, "mysql://"):
		// Likely a postgres URL without scheme - common in legacy configs
		driverName = postgresDriver
		connStr = "postgres://" + connStr
	case strings.HasPrefix(connStr, "mysql://"):
		driverName = mysqlDriver
		// Strip the mysql:// prefix for go-sql-driver/mysql
		connStr = strings.TrimPrefix(connStr, "mysql://")
	case strings.HasPrefix(connStr, "sqlite3://") || strings.HasPrefix(connStr, "sqlite://"):
		driverName = sqliteDriver
		// Strip the prefix
		connStr = strings.TrimPrefix(connStr, "sqlite3://")
		connStr = strings.TrimPrefix(connStr, "sqlite://")
	case strings.HasSuffix(connStr, ".db") || strings.HasSuffix(connStr, ".sqlite"):
		// Assume SQLite for .db or .sqlite files
		driverName = sqliteDriver
	default:
		err = errors.New("unsupported database connection string format (supports postgres://, mysql://, sqlite://)")
		return result, err
	}

	// Open database connection
	var db *sql.DB
	db, err = sql.Open(driverName, connStr)
	if err != nil {
		err = fmt.Errorf("failed to open database: %w", err)
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
		err = fmt.Errorf("failed to ping database: %w", err)
		_ = db.Close()
		return result, err
	}

	logger.Info("Database client initialized successfully")

	result = &DatabaseClient{
		db:     db,
		logger: logger,
	}

	return result, err
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
