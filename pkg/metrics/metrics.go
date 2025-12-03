package metrics

import "github.com/prometheus/client_golang/prometheus"

// Label constants.
const (
	InvestigationType = "type"
	Status            = "status"
	Namespace         = "namespace"
	ResourceType      = "resource_type"
	TokenType         = "token_type"
)

var (
	//nolint:gochecknoglobals // This is how the prometheus magic works.
	// InvestigationsStartedTotal Total number of investigations started.
	InvestigationsStartedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "investigations_started_total",
			Help: "Total number of investigations started",
		},
		[]string{InvestigationType},
	)

	//nolint:gochecknoglobals // This is how the prometheus magic works.
	// InvestigationsResolvedTotal Total number of investigations resolved.
	InvestigationsResolvedTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "investigations_resolved_total",
			Help: "Total number of investigations resolved",
		},
		[]string{InvestigationType},
	)

	//nolint:gochecknoglobals // This is how the prometheus magic works.
	// ClaudeAPICallsTotal Total number of Claude API calls.
	ClaudeAPICallsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "claude_api_calls_total",
			Help: "Total number of Claude API calls",
		},
		[]string{Status},
	)

	//nolint:gochecknoglobals // This is how the prometheus magic works.
	// ClaudeAPITokensTotal Total number of tokens used by Claude API.
	ClaudeAPITokensTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "claude_api_tokens_total",
			Help: "Total number of tokens used by Claude API",
		},
		[]string{TokenType},
	)

	//nolint:gochecknoglobals // This is how the prometheus magic works.
	// K8sQueriesTotal Total number of Kubernetes queries.
	K8sQueriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "k8s_queries_total",
			Help: "Total number of Kubernetes queries",
		},
		[]string{Namespace, ResourceType},
	)

	//nolint:gochecknoglobals // This is how the prometheus magic works.
	// LokiQueriesTotal Total number of Loki queries.
	LokiQueriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "loki_queries_total",
			Help: "Total number of Loki queries",
		},
		[]string{Status},
	)

	//nolint:gochecknoglobals // This is how the prometheus magic works.
	// ToolExecutionsTotal Total number of tool executions by Claude.
	ToolExecutionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "tool_executions_total",
			Help: "Total number of tool executions by Claude",
		},
		[]string{"tool_name", Status},
	)

	//nolint:gochecknoglobals // This is how the prometheus magic works.
	// ConversationsActive Current number of active conversations.
	ConversationsActive = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "conversations_active",
			Help: "Current number of active conversations",
		},
	)
)

//nolint:gochecknoinits // This is how the prometheus magic works.
func init() {
	_ = prometheus.Register(InvestigationsStartedTotal)
	_ = prometheus.Register(InvestigationsResolvedTotal)
	_ = prometheus.Register(ClaudeAPICallsTotal)
	_ = prometheus.Register(ClaudeAPITokensTotal)
	_ = prometheus.Register(K8sQueriesTotal)
	_ = prometheus.Register(LokiQueriesTotal)
	_ = prometheus.Register(ToolExecutionsTotal)
	_ = prometheus.Register(ConversationsActive)
}
