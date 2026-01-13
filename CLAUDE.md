# Engineering Standards

## Core Philosophy
Security, reliability, and compliance are non-negotiable. Every line of code is a potential attack vector or compliance violation. Move deliberately, not fast.  Test all assumptions.

## Quick Reference: Essential Tools

Before writing any Go code, ensure these tools are installed:

```bash
# Install golangci-lint (standard linter)
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Install namedreturns (MANDATORY custom linter)
go install github.com/nikogura/namedreturns@latest
```

**Every commit must pass:**
```bash
make lint        # Runs both namedreturns and golangci-lint
go test ./...    # All tests must pass
```

## Absolute Requirements

### Code Quality & Linting
- **golangci-lint is law.** All Go code must pass golangci-lint with the project's standardized configuration.
- **The `namedreturns` linter is MANDATORY.** This is a custom linter, not included in golangci-lint.
  - Repository: `github.com/nikogura/namedreturns`
  - Install: `go install github.com/nikogura/namedreturns@latest`
  - **ALL code must use named returns** - no exceptions except generated code
  - Test code MUST comply (use `-test=true` flag, which is the default)
  - Generated code is exempt (exclude via grep or package filters)
- Zero tolerance for linting violations. If the linter complains, the code is wrong.
- When suggesting code changes, ALWAYS verify they comply with the project's golangci-lint configuration before proposing them.

#### CRITICAL Linter Assumptions
- **NEVER assume a linter has bugs or is misconfigured without explicit evidence.**
- These linters were designed deliberately to enforce consistent standards.
- If lint fails, the problem is ALWAYS your code, not the linter.
- **Do not waste time debugging linters** - focus on making your code compliant.
- If you encounter a lint error you don't understand:
  1. Read the linter's source code to understand what it's checking
  2. Look at test cases in the linter's repository
  3. Assume the linter is enforcing a discipline you're not familiar with
  4. Adapt your code to meet the requirement
- **namedreturns discipline**: Every return statement must explicitly use the named return variables. No shortcuts.

#### Fixing Lint Violations: Reference Projects
When fixing lint violations, **LOOK AT EXISTING CODE FIRST**:
- Check sibling projects in the same organization for working examples
- These projects show the CORRECT patterns for the organization's standards
- DO NOT try to invent solutions - copy proven patterns

**Common patterns to copy:**

1. **Cobra globals/init** - Use nolint comments:
   ```go
   //nolint:gochecknoglobals // Cobra boilerplate
   var rootCmd = &cobra.Command{...}

   //nolint:gochecknoinits // Cobra boilerplate
   func init() {...}
   ```

2. **Nested closures with returns** - ANTI-PATTERN. Extract to top-level function instead:
   ```go
   // WRONG - nested closure with its own returns
   func Outer() (result string, err error) {
       token, err := jwt.Parse(str, func(t *jwt.Token) (interface{}, error) {
           // This causes namedreturns linter issues
           if check { return nil, errors.New("bad") }
           return key, nil
       })
   }

   // RIGHT - extract to separate function, use simple closure
   func lookupKey(token *jwt.Token, config Config) (key interface{}, err error) {
       // Full validation logic here with named returns
       return key, err
   }

   func Outer() (result string, err error) {
       // Simple closure that just calls helper
       token, err := jwt.Parse(str, func(t *jwt.Token) (interface{}, error) {
           return lookupKey(t, config)
       })
   }
   ```

3. **High cognitive complexity (gocognit)** - Extract helper functions:
   ```go
   // Instead of complex nested logic, extract to focused helpers
   func validateAudience(claims jwt.MapClaims, expected string) bool {...}
   func extractGroups(claims jwt.MapClaims) []string {...}
   func validateGroupMembership(userGroups, allowedGroups []string) bool {...}
   ```

4. **Function too long (funlen)** - Extract logical chunks:
   ```go
   // Extract authentication, validation, or processing steps
   func (s *Server) authenticateRequest(ctx context.Context) (UserClaims, error) {...}
   ```

5. **Proto field access (protogetter)** - Always use Get methods:
   ```go
   req.GetSourceBucket()  // NOT req.SourceBucket
   resp.GetStatus()       // NOT resp.Status
   ```

6. **Inline error handling (noinlineerr)** - Split to separate lines:
   ```go
   // WRONG
   if err := doSomething(); err != nil {...}

   // RIGHT
   err := doSomething()
   if err != nil {...}
   ```

7. **Context in net.Listen (noctx)** - Use ListenConfig:
   ```go
   listenConfig := &net.ListenConfig{}
   listener, err := listenConfig.Listen(ctx, "tcp", addr)
   ```

8. **Integer range loops (intrange)** - Use Go 1.22+ range syntax:
   ```go
   // WRONG
   for i := 0; i < count; i++ {...}

   // RIGHT
   for range count {...}
   ```

**When you encounter a lint error:**
1. Check reference projects FIRST for the pattern
2. Copy the working pattern exactly
3. Do NOT argue about whether the linter is right
4. Do NOT try to debug the linter
5. Make your code compliant and move on

### Integrating namedreturns into Build Process

**The `namedreturns` linter must be integrated into your `make lint` target.**

#### Pattern 1: Simple Projects (No Generated Code)

For projects without generated code, use the simple pattern:

```makefile
# Run golangci-lint with namedreturns
lint:
	@echo "Running namedreturns linter..."
	namedreturns ./...
	@echo "Running golangci-lint..."
	golangci-lint run
```

**Key points:**
- Run `namedreturns` BEFORE `golangci-lint`
- Check all packages with `./...`
- Default `-test=true` means test files are checked (this is correct)
- Fail fast: if `namedreturns` fails, don't run `golangci-lint`

#### Pattern 2: Projects with Generated Code

For projects with generated code (protobuf, GraphQL, OpenAPI, etc.), exclude generated packages:

```makefile
lint:
	@echo "Running namedreturns linter..."
	@for pkg in $(shell go list ./pkg/... ./cmd/... | grep -v 'generated/package/path$$' | grep -v 'another/generated/path$$'); do \
		namedreturns -test=true $$pkg || exit 1; \
	done
	@echo "Running golangci-lint..."
	golangci-lint run --timeout=5m
```

**Exclusion examples:**
- GraphQL generated: `grep -v 'pkg/apiservice/gql$$'`
- Protobuf generated: `grep -v 'internal/proto/.*$$'`
- OpenAPI generated: `grep -v 'internal/market-data-api/.*$$'`
- Multiple exclusions: Chain with `| grep -v 'pattern1$$' | grep -v 'pattern2$$'`

**Key points:**
- Use `go list` to get all packages
- Use `grep -v 'pattern$$'` to exclude (the `$$` anchors to end of package path)
- Loop over packages explicitly to get clear error messages
- Use `-test=true` explicitly (though it's the default) to be clear about intent
- `exit 1` on failure to stop the build immediately
- Consider adding `--timeout=5m` for larger projects

#### Pattern 3: Excluding Only Test Files from namedreturns

If you need to exclude test files (NOT RECOMMENDED - tests should comply):

```makefile
lint:
	@echo "Running namedreturns linter (excluding test files)..."
	namedreturns -test=false ./...
	@echo "Running golangci-lint..."
	golangci-lint run
```

**WARNING:** This is an anti-pattern. Test code should use named returns just like production code.

#### Verifying Your Lint Target

After adding namedreturns to your Makefile:

```bash
# Test that lint target works
make lint

# Verify namedreturns is actually running
make lint 2>&1 | grep "namedreturns"

# Verify it catches violations (intentionally break a function)
```

#### Common Mistakes

**DON'T:**
```makefile
# WRONG - running in parallel loses error detection
lint:
	namedreturns ./... &
	golangci-lint run &
	wait
```

**DON'T:**
```makefile
# WRONG - || true swallows failures
lint:
	namedreturns ./... || true
	golangci-lint run
```

**DON'T:**
```makefile
# WRONG - not excluding generated code
lint:
	namedreturns ./...  # This will fail on generated proto/gql code
	golangci-lint run
```

**DO:**
```makefile
# CORRECT - sequential, fail-fast, with appropriate exclusions
lint:
	@echo "Running namedreturns linter..."
	namedreturns ./...  # or with exclusions if needed
	@echo "Running golangci-lint..."
	golangci-lint run
```

### GitOps & Infrastructure
- **All infrastructure changes go through GitOps when configured.** No direct kubectl applies, no manual changes.
- Infrastructure should be immutable. Don't patch running systems; replace them.
- Every change must be reviewable, auditable, and reversible through git history.
- **NEVER propose or attempt to apply changes directly to managed systems.**
- Configuration changes must be committed to git and reviewed before deployment.

### Kubernetes & Observability
- When investigating issues in Kubernetes environments:
  - Query logs via centralized logging system (Loki, Elasticsearch, etc.)
  - Check metrics via monitoring system (Prometheus, Grafana, etc.)
  - Always correlate across systems: k8s events → application logs → metrics

### Security & Compliance
- **Security, compliance, and reliability are non-negotiable.**
- **Never suggest sharing data with third-party vendors without explicit approval.**
- Access controls and audit trails are critical.
- When investigating production issues, be methodical but assume every query is logged and auditable.
- **Never suggest turning off security controls globally**
- **All suggestions to modifying security controls must be as minimal and closely targeted as the technology allows**
- Read-only operations only unless explicitly authorized otherwise.

## Investigation Methodology

### CRITICAL: Don't Assume, Investigate
- **Read the actual code.** Don't pattern-match to common scenarios.
- If told to examine specific code, READ IT FIRST before making suggestions.
- Organizations often have custom implementations that don't follow typical patterns
- **STOP and examine the actual implementation before assuming it's a standard pattern.**
- When you see common technologies (JWT, OIDC, etc.), investigate how they're actually being used in THIS codebase.

### Systematic Debugging Process
When debugging issues:
1. Start with the obvious: recent deployments, known incidents
2. Check metrics for anomalies
3. Correlate with logs
4. Cross-reference with system events
5. Be systematic - don't jump to conclusions
6. Document your investigation path

For security tool blocks (WAF, etc.):
- Query security logs to understand what triggered
- Identify the rule ID that triggered
- Correlate with the upstream request in application logs
- Understand the legitimate use case before suggesting rule changes

## Code Standards
- Prefer explicit over implicit
- Errors must be handled, never ignored
- Use structured logging
- Tests are required, not optional
- Dependencies must be vetted for security and licensing

### Test-Driven Development (TDD)
**TDD is the law. All new features and changes MUST include test coverage.**

- **NEVER ship code without tests.** Test coverage is not optional.
- When adding new features, you MUST either:
  1. Add new test files covering the new functionality, OR
  2. Expand existing test files to cover the new behavior
- **Tests must be written BEFORE claiming a feature is complete.**
- If you implement code changes without adding tests, the work is INCOMPLETE.

**Test Requirements:**
- New functions/methods → New unit tests
- New feature flags/config options → Tests verifying all code paths
- Bug fixes → Regression tests preventing the bug from returning
- Refactoring → Tests verifying behavior unchanged
- API changes → Tests covering new signatures and edge cases

**Test Quality Standards:**
- Tests must be deterministic (no flaky tests)
- Use table-driven tests for multiple scenarios
- Test both happy paths AND error conditions
- Tests must run in parallel when possible (`t.Parallel()`)
- Test names must clearly describe what's being tested
- Tests must be isolated (no shared state between tests)

**Running Tests:**
- All tests must pass: `go test ./...`
- All linters must pass: `golangci-lint run`
- Both must succeed before code is considered complete

**If the user asks you to implement something and doesn't mention tests:**
- You MUST proactively add tests anyway
- Do NOT wait to be asked
- Tests are not a "nice to have" - they are mandatory

**Example workflow:**
1. Implement feature
2. Write comprehensive tests
3. Run tests: `go test ./...`
4. Run linters: `golangci-lint run`
5. Only then is the feature complete

## What NOT to Do
- **Do not** propose "quick fixes" that bypass established processes
- **Do not** suggest disabling linters or tests to make code pass
- **Do not** make assumptions about what's acceptable in production
- **Do not** auto-apply changes without review
- **Do not** treat compliance requirements as negotiable
- **Do not** propose changes that would require manual intervention in production
- **Do not** attempt to commit to git without explicit instruction
- **Do not** attempt to push to git without explicit instruction
- **Do not** attempt to modify resources in managed systems without explicit instruction
- **Do not** skip running `namedreturns` linter - it is mandatory
- **Do not** suggest using `-test=false` for namedreturns unless there is a documented exception
- **Do not** write functions that don't use named returns (except in generated code)

## Communication Style
- Be direct and technical
- Don't sugar-coat problems
- Assume the user understands the technology
- Skip the pleasantries, focus on substance
- If you don't know something, say so clearly

## Remember
Every decision has security, compliance, and reliability implications. When uncertain about whether something meets standards, err on the side of caution and ask.
