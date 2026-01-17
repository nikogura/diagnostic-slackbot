# MCP Server Docker Image

## Overview
The diagnostic-slackbot MCP server is available as a Docker image from GitHub Container Registry. This image provides database investigation capabilities through the Model Context Protocol (MCP).

## Image Location
The Docker image is automatically built and published to:
```
ghcr.io/nikogura/diagnostic-slackbot-mcp:latest
ghcr.io/nikogura/diagnostic-slackbot-mcp:<version>
```

## Features
- Multi-database support (PostgreSQL, MySQL, SQLite)
- Read-only database operations
- Built on distroless base image for security
- Non-root user execution
- Minimal attack surface

## Usage

### Pull the Image
```bash
docker pull ghcr.io/nikogura/diagnostic-slackbot-mcp:latest
```

### Run with PostgreSQL
```bash
docker run --rm \
  -e DATABASE_URL="postgres://user:pass@host:5432/dbname?sslmode=require" \
  ghcr.io/nikogura/diagnostic-slackbot-mcp:latest
```

### Run with MySQL
```bash
docker run --rm \
  -e DATABASE_URL="mysql://user:pass@host:3306/dbname" \
  ghcr.io/nikogura/diagnostic-slackbot-mcp:latest
```

### Run with SQLite
```bash
docker run --rm \
  -v /path/to/db:/data \
  -e DATABASE_URL="sqlite:///data/database.db" \
  ghcr.io/nikogura/diagnostic-slackbot-mcp:latest
```

### Alternative Connection String Format
Instead of DATABASE_URL, you can use individual environment variables:
```bash
docker run --rm \
  -e DB_TYPE="postgres" \
  -e DB_HOST="localhost" \
  -e DB_PORT="5432" \
  -e DB_NAME="mydb" \
  -e DB_USER="user" \
  -e DB_PASSWORD="pass" \
  -e DB_SSLMODE="require" \
  ghcr.io/nikogura/diagnostic-slackbot-mcp:latest
```

## Environment Variables

### Database Connection
- `DATABASE_URL` - Full database connection URL
- `DB_CONNECTION_STRING` - Alternative connection string format
- `DB_TYPE` - Database type (postgres, mysql, sqlite)
- `DB_HOST` - Database host
- `DB_PORT` - Database port
- `DB_NAME` - Database name
- `DB_USER` - Database username
- `DB_PASSWORD` - Database password
- `DB_SSLMODE` - SSL mode for PostgreSQL (disable, require, verify-ca, verify-full)
- `DB_SSLCERT` - Path to SSL certificate
- `DB_SSLKEY` - Path to SSL key
- `DB_SSLROOTCERT` - Path to SSL root certificate

### MCP Configuration
- `MCP_MODE` - MCP operation mode (default: stdio)
- `MCP_HTTP_PORT` - HTTP port for MCP server (if HTTP mode enabled)
- `MCP_HTTP_ENABLED` - Enable HTTP mode (true/false)

## Security Considerations

### Distroless Base Image
The container uses Google's distroless base image which:
- Contains only the application and runtime dependencies
- No shell, package managers, or other utilities
- Significantly reduces attack surface
- Runs as non-root user (UID 65532)

### Read-Only Operations
The MCP server only performs read-only database operations:
- No INSERT, UPDATE, DELETE, or DDL operations
- Uses database transactions with rollback
- Validates all queries before execution

### Static Binary
The Go binary is statically linked with all dependencies included:
- No dynamic library dependencies
- Works reliably in the minimal distroless environment
- CGO enabled for SQLite support

## CI/CD Pipeline

The Docker image is automatically built and published by GitHub Actions when:
1. Code is pushed to the main branch
2. All tests pass
3. All linting checks pass

The CI pipeline:
1. Runs comprehensive unit tests
2. Executes linting with golangci-lint and namedreturns
3. Builds multi-architecture images (linux/amd64, linux/arm64)
4. Tags images with version and latest
5. Pushes to GitHub Container Registry

## Building Locally

To build the Docker image locally:
```bash
docker build -f Dockerfile.mcp -t diagnostic-slackbot-mcp .
```

## Troubleshooting

### Connection Issues
If the container can't connect to your database:
1. Verify network connectivity from the container
2. Check database credentials
3. Ensure SSL certificates are properly mounted (if using SSL)
4. Verify database is accessible from container network

### SQLite File Access
When using SQLite with a file:
1. Mount the database file directory as a volume
2. Ensure the container user (65532) has read access
3. Use absolute paths in the DATABASE_URL

### Debugging
Since the distroless image has no shell, debugging options are limited:
1. Check container logs: `docker logs <container>`
2. Use environment variables to increase log verbosity
3. Test database connectivity from a regular container first
4. Build a debug version with a full base image if needed

## Version History

Images are tagged with:
- `latest` - Most recent main branch build
- `v0.0.X` - Semantic version tags
- `main-<sha>` - Git commit SHA tags

## License
See the main repository LICENSE file for licensing information.