# Build stage
FROM golang:1.24 AS builder

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build static binaries for distroless
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-w -s' -o /bin/diagnostic-slackbot ./cmd/bot
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags '-w -s' -o /bin/mcp-server ./cmd/mcp-server

# Final stage - distroless
FROM gcr.io/distroless/base-debian12:nonroot

# Set working directory
WORKDIR /app

# Copy binaries from builder
COPY --from=builder /bin/diagnostic-slackbot /app/diagnostic-slackbot
COPY --from=builder /bin/mcp-server /app/mcp-server

# Investigation templates are mounted from Vault secrets at runtime

# Copy engineering standards
COPY --chown=65532:65532 CLAUDE.md /app/docs/CLAUDE.md

# Copy MCP configuration
COPY --chown=65532:65532 .mcp.json /app/.mcp.json

# Copy LaTeX templates (not in reports/ - that's for generated PDFs)
COPY --chown=65532:65532 latex-templates/ /app/latex-templates/

# Copy entrypoint script
COPY --chown=65532:65532 entrypoint.sh /app/entrypoint.sh

# User is already nonroot (65532) in distroless

# Expose no ports (Socket Mode doesn't need inbound connections)

# Set default environment variables
ENV INVESTIGATION_DIR=/app/investigations \
    CLAUDE_MD_PATH=/app/docs/CLAUDE.md \
    PATH=/usr/local/bin:/usr/bin:/bin

# Health check (check if process is running)
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD pgrep -f diagnostic-slackbot || exit 1

# Run the bot via entrypoint script
ENTRYPOINT ["/app/entrypoint.sh"]
