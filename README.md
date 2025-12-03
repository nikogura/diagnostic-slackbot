# Diagnostic Slackbot

A Slack bot that enables self-service production diagnostics by integrating Claude Code CLI with Kubernetes, Loki, and observability tools. The bot provides autonomous investigation capabilities through YAML-based templates and custom MCP tools, delivering professional PDF reports directly in Slack.

## Features

- **Claude Code Integration**: Uses Claude Code CLI with MCP server for advanced tool use capabilities
- **MCP Server**: Custom tools for Loki queries, K8s access, GitHub integration, ECR scanning, and PDF generation
- **Investigation Templates**: YAML-based templates define structured investigation workflows
- **Kubernetes Access**: Read-only access to pods, logs, ConfigMaps, Deployments, and Flux CRDs
- **PDF Report Generation**: Automated professional reports with company branding via Pandoc + LaTeX
- **Log Sanitization**: Comprehensive PII and secret redaction (13 regex patterns)
- **Slack Socket Mode**: Supports app mentions, threads, and conversational follow-ups
- **Conversation State**: In-memory tracking with 24-hour expiry and automatic file cleanup
- **Prometheus Metrics**: Full observability with counters for investigations, API calls, K8s queries, and tool usage

## Code Quality

- **Linter Compliance**: 100% clean - all golangci-lint and namedreturns checks pass
- **Test Coverage**: Unit tests with race detection, coverage reporting to Codecov
- **CI/CD**: Automated linting, testing, Docker builds, and security scanning via GitHub Actions
- **Multi-arch Support**: Docker images for amd64 and arm64
- **Security Scanning**: Trivy vulnerability scanning with SARIF upload

## Project Structure

```
diagnostic-slackbot/
├── cmd/
│   ├── bot/main.go                  # Main Slack bot entry point
│   └── mcp-server/main.go           # MCP server for Claude Code tools
├── pkg/
│   ├── bot/                         # Slack bot logic
│   │   ├── bot.go                   # Core bot initialization
│   │   ├── handlers.go              # Event handlers
│   │   ├── claudecode.go            # Claude Code CLI integration
│   │   └── state.go                 # Conversation state management
│   ├── claude/                      # Direct Claude API integration (legacy)
│   │   ├── client.go                # API client with tool use support
│   │   ├── tools.go                 # Tool definitions for Claude
│   │   └── prompts.go               # System prompt construction
│   ├── investigations/              # Investigation template system
│   │   ├── template.go              # Template data structures and loading
│   │   └── matcher.go               # Message matching logic
│   ├── k8s/                         # Kubernetes and Loki clients
│   │   ├── agent.go                 # K8s resource access
│   │   ├── loki.go                  # Loki log query client
│   │   └── sanitizer.go             # Log sanitization
│   ├── mcp/                         # MCP server implementation
│   │   ├── server.go                # MCP protocol and tool handlers
│   │   ├── types.go                 # MCP protocol types
│   │   └── ecr.go                   # ECR vulnerability scanning
│   └── metrics/                     # Prometheus metrics
│       ├── metrics.go               # Metric definitions
│       └── server.go                # HTTP metrics server
├── investigations/                  # YAML investigation templates
│   ├── modsecurity-block.yaml
│   ├── atlas-migration.yaml
│   ├── general-diagnostic.yaml
│   └── ecr-vulnerability-scan.yaml
├── latex-templates/                 # PDF report templates
├── docs/
│   ├── ECR_INTEGRATION.md           # ECR vulnerability scanning guide
│   └── PROJECT_SPEC.md              # Original project specification
├── .github/workflows/               # CI/CD pipelines
│   ├── ci.yaml                      # Lint, test, build, Docker push
│   └── release.yaml                 # GoReleaser for versioned releases
├── Dockerfile                       # Multi-stage Alpine build
├── Makefile                         # Build and lint targets
├── .golangci.yml                    # Linter configuration (strict enforcement)
├── .mcp.json                        # MCP server configuration
└── go.mod                           # Go module dependencies
```

## Investigation Templates

The bot includes example investigation templates in the `investigations/` directory. These are generic examples with substitution variables for adaptation to your environment.

### Included Examples

#### ModSecurity WAF Block Diagnosis

Investigates Web Application Firewall blocks with the following capabilities:

- Queries Loki for ModSecurity audit logs
- Analyzes OWASP CRS rule triggers
- Categorizes blocks (false positive vs legitimate)
- Provides exact remediation with rule IDs and config snippets
- Performs IP geolocation via whois

**Trigger patterns**: `modsec`, `modsecurity`, `waf blocked`, `403.*waf`

#### Atlas Migration Troubleshooting

Diagnoses why Atlas migrations are not being applied in GitOps environments:

- Checks AtlasMigration CRD status
- Verifies GitRepository version pinning
- Inspects ConfigMap contents
- Analyzes Flux Kustomization reconciliation
- Identifies root cause (tag pinning, ConfigMap not regenerated, etc.)

**Trigger patterns**: `atlas.*migration`, `migration.*not.*applied`, `migration.*failure`

#### General Diagnostic Investigation

A systematic approach for general production issues:

- Defines investigation phases (scope, context gathering, hypothesis formation, targeted investigation, root cause analysis, remediation)
- Provides examples for querying Prometheus, Thanos, Loki, and Alertmanager
- Covers common patterns (WAF blocks, database migrations, Flux failures, pod crashes)
- Emphasizes security-first and GitOps principles

**Trigger patterns**: `investigate`, `diagnostic`, `troubleshoot`, `issue`, `problem`, `error`

## Creating New Investigations

### Investigation YAML Structure

Investigations are defined in YAML files with the following structure:

```yaml
name: "Investigation Name"
description: "Brief description of what this investigation does"
trigger_patterns:
  - "pattern1"
  - "pattern2.*regex"
  - "specific phrase"

initial_prompt: |
  Multi-line prompt that Claude will use as context for this investigation.

  This should include:
  - Role definition ("You are a diagnostic agent for...")
  - Core principles (security, read-only, systematic approach)
  - Investigation methodology (phases, steps)
  - Available tools and when to use them
  - Output format expectations
  - Critical patterns to recognize
  - Communication style guidelines

kubernetes_resources:
  - type: "pod"
    namespace: "namespace-name"
    selector: "app=component"
    container: "container-name"
    since: "1h"
    grep: "ERROR"
    tail_lines: 500

require_approval: false
```

### Field Descriptions

- **name**: Human-readable name shown in Slack
- **description**: Brief description (prefix with "EXAMPLE:" if this is a template for customization)
- **trigger_patterns**: Regex patterns matched against user messages. More specific patterns (longer solid pattern length) take precedence.
- **initial_prompt**: The system prompt Claude receives. This is the core of your investigation workflow.
- **kubernetes_resources**: (Optional) List of K8s resources to pre-fetch. Useful for common queries.
- **require_approval**: (Optional) If true, bot asks user for confirmation before starting investigation.

### Substitution Variables

Use `{{VARIABLE_NAME}}` syntax for environment-specific values that need to be customized for production deployment:

```yaml
initial_prompt: |
  Query Prometheus at {{PROMETHEUS_URL}} for metrics.
  Check Loki at {{LOKI_URL}} for logs.
  The application runs in namespace {{APP_NAMESPACE}}.
```

**Common substitution variables:**
- `{{PROMETHEUS_URL}}` - Prometheus endpoint
- `{{THANOS_URL}}` - Thanos query endpoint (federated metrics)
- `{{LOKI_URL}}` - Loki log aggregation endpoint
- `{{ALERTMANAGER_URL}}` - Alertmanager endpoint
- `{{REALM}}` - Environment name (prod, staging, dev)
- `{{NAMESPACE}}` - Kubernetes namespace
- `{{DOMAIN}}` - Application domain
- `{{GH_ORG}}` - GitHub organization
- `{{GH_REPO}}` - GitHub repository name

### Trigger Pattern Specificity

The bot uses a specificity algorithm to select the best matching investigation:

1. Patterns are tested in order against the user's message
2. If multiple patterns match, the most specific wins
3. Specificity = length of longest solid pattern (non-regex characters)

**Examples:**
- `"atlas.*migration"` → specificity = 5 (longest solid: "atlas")
- `"migration.*not.*applied"` → specificity = 9 (longest solid: "migration")
- `"database migration failure"` → specificity = 25 (entire phrase is solid)

**Best practices:**
- Use specific phrases for narrow investigations
- Use regex patterns for flexibility within a domain
- Longer solid patterns win ties

### Available Claude Tools (via MCP Server)

Your investigation prompt should reference these tools that Claude can autonomously use:

- **query_loki**: Query Loki using LogQL syntax
  ```
  Parameters: query (LogQL string), start_time (relative like "1h" or RFC3339), end_time, limit
  ```

- **whois_lookup**: IP geolocation
  ```
  Parameters: ip_address
  ```

- **generate_pdf**: Convert Markdown to PDF report
  ```
  Parameters: markdown_content (string), filename (optional)
  ```

- **github_get_file**: Fetch file from GitHub repository
  ```
  Parameters: owner, repo, path, ref (optional branch/tag)
  ```

- **github_list_directory**: List directory contents
  ```
  Parameters: owner, repo, path
  ```

- **github_search_code**: Search code across repositories
  ```
  Parameters: query, owner (optional)
  ```

- **ecr_scan_results**: Query ECR vulnerability scans
  ```
  Parameters: repository_name, account_ids (list), severity_filter (optional)
  ```

**Note:** The legacy direct K8s tool calls (`get_k8s_pod_logs`, `get_k8s_resource`, etc.) are deprecated in favor of the MCP server architecture. Investigation templates should primarily use `query_loki` for log access and focus on log analysis rather than direct K8s API calls.

### Investigation Prompt Guidelines

Your `initial_prompt` should:

1. **Define the role clearly**: "You are a diagnostic agent for X platform investigating Y issues..."

2. **Set boundaries**: Emphasize read-only access, security considerations, GitOps principles

3. **Provide methodology**: Step-by-step investigation phases or decision trees

4. **List available tools**: Explain when to use each tool with examples

5. **Define output format**: Specify structure (Summary, Timeline, Root Cause, Remediation, Prevention)

6. **Include critical patterns**: Known issues, false positive indicators, common root causes

7. **Set communication style**: Technical depth, conciseness, use of severity labels

8. **Document substitution variables**: List all `{{VARIABLES}}` at the end with descriptions

### Testing Locally

1. **Create your investigation YAML** in `investigations/my-investigation.yaml`

2. **Substitute variables** for local testing:
   ```bash
   # Use sed or your editor to replace {{VARIABLES}} with actual values
   sed -e 's|{{LOKI_URL}}|http://localhost:3100|g' \
       -e 's|{{NAMESPACE}}|default|g' \
       investigations/my-investigation.yaml > /tmp/test-investigation.yaml
   ```

3. **Run validation tests**:
   ```bash
   # Tests validate YAML structure and pattern matching
   go test ./pkg/investigations/... -v
   ```

4. **Test with bot locally**:
   ```bash
   export INVESTIGATION_DIR=/tmp
   export SLACK_BOT_TOKEN=xoxb-your-token
   export SLACK_APP_TOKEN=xapp-your-token
   export ANTHROPIC_API_KEY=sk-your-key
   export LOKI_ENDPOINT=http://localhost:3100

   go run cmd/bot/main.go
   ```

5. **Send test message in Slack** matching your trigger patterns

### Deploying to Production

For production deployment using Vault-backed secrets:

1. **Substitute production values** in your investigation YAML (replace all `{{VARIABLES}}`)

2. **Store in Vault** (example for HashiCorp Vault):
   ```bash
   vault kv put infra/diagnostic-slackbot-inv-myinvestigation \
     my-investigation.yaml=@investigations/my-investigation.yaml
   ```

3. **Create VaultStaticSecret manifest**:
   ```yaml
   apiVersion: secrets.hashicorp.com/v1beta1
   kind: VaultStaticSecret
   metadata:
     name: diagnostic-slackbot-inv-myinvestigation
     namespace: diagnostic-slackbot
   spec:
     type: kv-v2
     mount: infra
     path: diagnostic-slackbot-inv-myinvestigation
     destination:
       name: diagnostic-slackbot-inv-myinvestigation
       create: true
     refreshAfter: 30s
     vaultAuthRef: diagnostic-slackbot
     rolloutRestartTargets:
       - kind: Deployment
         name: diagnostic-slackbot
   ```

4. **Mount secret in Deployment**:
   ```yaml
   volumeMounts:
     - name: inv-myinvestigation
       mountPath: /app/investigations/my-investigation.yaml
       subPath: my-investigation.yaml
       readOnly: true
   volumes:
     - name: inv-myinvestigation
       secret:
         secretName: diagnostic-slackbot-inv-myinvestigation
   ```

5. **Apply with GitOps** - commit manifests and let Flux reconcile

### Example: Creating a Custom Investigation

Let's create an investigation for Nginx ingress controller issues:

```yaml
name: "Nginx Ingress Troubleshooting"
description: "Diagnoses Nginx ingress controller issues (502/504, SSL, routing)"
trigger_patterns:
  - "nginx.*ingress"
  - "502.*bad.*gateway"
  - "504.*gateway.*timeout"
  - "ingress.*not.*working"

initial_prompt: |
  You are diagnosing Nginx ingress controller issues in a Kubernetes environment.

  ## Investigation Steps

  1. **Check ingress controller pods**:
     - Use list_k8s_pods with namespace={{INGRESS_NAMESPACE}}, selector="app.kubernetes.io/name=ingress-nginx"
     - Look for restarts, OOMKilled, CrashLoopBackOff

  2. **Query recent logs**:
     - Use query_loki with: {namespace="{{INGRESS_NAMESPACE}}"} |= "error" or "warn"
     - Time range: last 1 hour
     - Look for upstream errors, SSL handshake failures, timeout messages

  3. **Check ingress resource**:
     - Use get_k8s_resource for the specific Ingress
     - Verify: backend service name, port, TLS config, annotations

  4. **Check backend pods**:
     - Use list_k8s_pods for backend service namespace
     - Verify pods are Running and Ready

  5. **Analyze error patterns**:
     - 502: Backend not responding (pod down, wrong service/port)
     - 504: Backend timeout (slow response, deadlock)
     - SSL errors: Certificate issues, TLS version mismatch

  ## Output Format

  ```
  ## Issue Summary
  [One-line description]

  ## Symptoms
  [What the user is experiencing]

  ## Root Cause
  [Specific cause identified]

  ## Remediation
  [Exact steps to fix with commands/configs]
  ```

  ## Substitution Variables
  - {{INGRESS_NAMESPACE}}: Namespace where ingress controller runs (e.g., "ingress-nginx")

kubernetes_resources:
  - type: "pod"
    namespace: "{{INGRESS_NAMESPACE}}"
    selector: "app.kubernetes.io/name=ingress-nginx"
    container: "controller"
    since: "1h"
    grep: "error"
    tail_lines: 200

require_approval: false
```

After creating this, substitute `{{INGRESS_NAMESPACE}}` with your actual namespace before deploying to production.

## Claude Tool Use via MCP Server

The bot uses Claude Code CLI with a custom MCP (Model Context Protocol) server that provides these tools for autonomous investigation:

### Available Tools

- **query_loki**: Query Loki log aggregation using LogQL syntax
  - Supports relative time (`1h`, `24h`) or RFC3339 timestamps
  - Automatic sanitization of results
  - Max 500 results to avoid token overflow

- **whois_lookup**: IP geolocation via ip-api.com
  - Returns country, ISP, ASN, organization
  - Useful for WAF block analysis

- **generate_pdf**: Convert Markdown to branded PDF reports
  - Uses Pandoc + custom LaTeX template
  - Automatic TOC, syntax highlighting, company branding
  - Files saved to `/tmp/` for automatic Slack upload

- **GitHub Tools** (requires `GITHUB_TOKEN`):
  - `github_get_file`: Fetch file contents from repositories
  - `github_list_directory`: List directory contents
  - `github_search_code`: Code search across repositories

- **ECR Tools** (requires AWS credentials):
  - `ecr_scan_results`: Query vulnerability scans across AWS accounts
  - Note: Currently has mock implementation (see docs/ECR_INTEGRATION.md)

### Architecture

The MCP server (`cmd/mcp-server/main.go`) is compiled as a separate binary and registered with Claude Code at container startup via `entrypoint.sh`. It communicates with Claude Code using JSON-RPC over stdio transport.

## Configuration

The bot is configured via environment variables:

**Required:**
- `SLACK_BOT_TOKEN` - Bot OAuth token (xoxb-...)
- `SLACK_APP_TOKEN` - App-level token for Socket Mode (xapp-...)
- `ANTHROPIC_API_KEY` - Claude API key (sk-ant-...)

**Optional:**
- `KUBECONFIG` - Path to kubeconfig (default: uses in-cluster config)
- `INVESTIGATION_DIR` - Path to investigation templates (default: `./investigations`)
- `CLAUDE_MD_PATH` - Path to engineering standards (default: `./docs/CLAUDE.md`)
- `LOKI_ENDPOINT` - Loki gateway endpoint (default: `http://loki-gateway.logging.svc.cluster.local`)
- `COMPANY_NAME` - Company name for PDF report branding (default: `Company`)
- `FILE_RETENTION` - File cleanup interval (default: `24h`)
- `GITHUB_TOKEN` - Personal access token for GitHub tools (optional)
- `AWS_*` - AWS credentials for ECR vulnerability scanning (optional)

## Building

```bash
# Run linters
make lint

# Run tests
make test

# Build binary
make build

# Build Docker image
make docker-build
```

## Usage

### Slack Commands

- `@bot help` - List available investigation types
- `@bot <problem description>` - Start an investigation
- Reply in thread to continue conversation

### Example Interactions

**ModSecurity Investigation:**
```
User: @bot I'm getting 403 errors from the WAF
Bot: 🔍 Starting ModSecurity WAF Block Diagnosis investigation...
Bot: [Queries Loki for recent 403s, analyzes rules, categorizes blocks]
Bot: Found 3 blocked requests in the last hour. Rule 930120 (OS File Access Attempt)
     triggered on cookie data. This appears to be a FALSE POSITIVE - the session
     cookie contains Base64 data that matches the pattern.

     Recommended fix:
     ```nginx
     SecRuleUpdateTargetById 930120 "!REQUEST_COOKIES:/__Secure-session-token/"
     ```
User: Can you check if this is happening in staging too?
Bot: [Queries Loki for staging realm, analyzes results]
```

**Atlas Migration Investigation:**
```
User: @bot migration 20251029093301 not showing up in dev-01
Bot: 🔍 Starting Atlas Migration Troubleshooting investigation...
Bot: [Checks GitRepository, ConfigMap, AtlasMigration CRD]
Bot: Root cause identified:

     dev-01 environment is pinned to tag 0.0.667 in control-kubernetes
     Migration 20251029093301 was added in tag 0.0.673

     Resolution: Update config to reference tag 0.0.673
```

## Security

- **Read-Only Access**: Bot has no write permissions to Kubernetes
- **Log Sanitization**: All logs are sanitized before sending to Claude API
  - API keys, tokens, passwords redacted
  - JWT tokens redacted
  - Email addresses redacted
  - Credit card numbers redacted
  - Private keys redacted
- **Audit Trail**: All K8s queries and Claude API calls are logged
- **GitOps Principles**: Never suggests direct cluster modifications

## Deployment

Deploy as a Kubernetes Deployment with:

- Single replica (in-memory state)
- Non-root container user (UID 1000)
- ServiceAccount with minimal RBAC:
  - `get`, `list` on pods, pods/log, configmaps, services
  - `get`, `list` on deployments
  - `get`, `list` on Flux CRDs (gitrepositories, kustomizations)
  - `get`, `list` on Atlas CRDs (atlasmigrations)

### RBAC Requirements

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: diagnostic-slackbot
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log", "configmaps", "services"]
  verbs: ["get", "list"]
- apiGroups: ["apps"]
  resources: ["deployments"]
  verbs: ["get", "list"]
- apiGroups: ["source.toolkit.fluxcd.io"]
  resources: ["gitrepositories"]
  verbs: ["get", "list"]
- apiGroups: ["kustomize.toolkit.fluxcd.io"]
  resources: ["kustomizations"]
  verbs: ["get", "list"]
- apiGroups: ["db.atlasgo.io"]
  resources: ["atlasmigrations"]
  verbs: ["get", "list"]
```

## Observability

The bot exposes Prometheus metrics on port `:9090` for scraping:

### Metrics

- `investigations_started_total{type}` - Total investigations initiated by template type
- `investigations_resolved_total{type}` - Total investigations completed
- `claude_api_calls_total{status}` - Claude API call counts (success/error)
- `claude_api_tokens_total{type="input|output"}` - Token usage tracking
- `k8s_queries_total{namespace,resource_type}` - Kubernetes query audit trail
- `loki_queries_total{status}` - Loki query tracking
- `tool_executions_total{tool_name,status}` - MCP tool usage statistics
- `conversations_active` - Current number of active conversations (gauge)

### Logging

Structured JSON logging via `log/slog` with:
- Severity levels (Debug, Info, Warn, Error)
- Context-aware logging (conversation IDs, user IDs)
- Automatic correlation for investigations

## Container Images

Docker images are automatically built and published to GitHub Container Registry:

```bash
# Pull latest image
docker pull ghcr.io/nikogura/diagnostic-slackbot:latest

# Pull specific version
docker pull ghcr.io/nikogura/diagnostic-slackbot:v1.0.0

# Run locally
docker run -e SLACK_BOT_TOKEN=xoxb-... \
           -e SLACK_APP_TOKEN=xapp-... \
           -e ANTHROPIC_API_KEY=sk-... \
           ghcr.io/nikogura/diagnostic-slackbot:latest
```

## CI/CD

The project uses GitHub Actions for continuous integration and deployment:

- **CI Pipeline** (`.github/workflows/ci.yaml`):
  - Runs on every push and pull request
  - Linting (golangci-lint + namedreturns)
  - Testing with race detection and coverage
  - Binary build
  - Multi-arch Docker image build (amd64, arm64)
  - Security scanning with Trivy
  - Publishes to `ghcr.io/nikogura/diagnostic-slackbot`

- **Release Pipeline** (`.github/workflows/release.yaml`):
  - Triggered on version tags (`v*`)
  - GoReleaser for multi-platform binaries
  - Docker images with semantic versioning
  - Automated changelog generation
  - GitHub Release creation

- **Dependabot** (`.github/dependabot.yml`):
  - Weekly dependency updates
  - Grouped updates for AWS SDK and Kubernetes

## License

Apache License 2.0

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linters: `make test && make lint`
5. Submit a pull request

## Maintainer

[Nik Ogura](https://github.com/nikogura)
