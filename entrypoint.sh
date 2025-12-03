#!/bin/sh
set -e

# Ensure .claude directory exists and copy MCP config
# Bot user owns /home/bot due to emptyDir mount
mkdir -p /home/bot/.claude
cp /app/.mcp.json /home/bot/.claude/mcp.json
chmod 644 /home/bot/.claude/mcp.json

echo "MCP config copied to /home/bot/.claude/mcp.json"

# Register MCP server automatically
# This is required because Claude Code in --print mode doesn't auto-discover from .mcp.json
cd /app
echo "Registering MCP server with Claude Code..."
claude mcp add --transport stdio diagnostic /app/mcp-server

# Verify registration
echo "Verifying MCP server registration..."
claude mcp list

echo "MCP server setup complete"

# Execute the main binary
exec /app/diagnostic-slackbot "$@"
