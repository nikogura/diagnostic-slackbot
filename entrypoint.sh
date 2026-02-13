#!/bin/sh
set -e

# Ensure .claude directory exists and copy MCP config
# Bot user owns /home/bot due to emptyDir mount
mkdir -p /home/bot/.claude
cp /app/.mcp.json /home/bot/.claude/mcp.json
chmod 644 /home/bot/.claude/mcp.json

echo "MCP config copied to /home/bot/.claude/mcp.json"

# Register MCP HTTP/SSE server
# Using HTTP/SSE transport for better performance (persistent connection, no process spawning)
cd /app
echo "Registering MCP HTTP/SSE server with Claude Code..."
claude mcp add --transport sse diagnostic http://localhost:8090/sse

# Verify registration
echo "Verifying MCP server registration..."
claude mcp list

echo "MCP HTTP/SSE server setup complete"

# Execute the main binary (which starts both Slack bot and HTTP MCP server)
exec /app/diagnostic-slackbot "$@"
