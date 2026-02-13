package auth

import (
	"net/http"
)

// Method represents an authentication method.
type Method interface {
	// Name returns the human-readable name of this auth method.
	Name() string

	// Authenticate attempts to authenticate the request.
	// Returns nil error if authentication succeeds, error otherwise.
	Authenticate(r *http.Request) (*Result, error)
}

// Result contains information about an authenticated request.
type Result struct {
	Authenticated bool     `json:"authenticated"`
	Username      string   `json:"username,omitempty"`
	Email         string   `json:"email,omitempty"`
	Groups        []string `json:"groups,omitempty"`
	Subject       string   `json:"subject,omitempty"`
	Method        string   `json:"method"` // Which auth method was used
}

// Config holds configuration for all authentication methods.
type Config struct {
	// Static token auth
	StaticToken string `json:"static_token,omitempty"`

	// JWT auth
	JWTSecret    string `json:"jwt_secret,omitempty"`
	JWTAlgorithm string `json:"jwt_algorithm,omitempty"` // HS256, RS256, etc.

	// API Key auth
	APIKeys map[string]string `json:"api_keys,omitempty"` // key -> username mapping

	// OIDC auth
	OIDCIssuerURL        string   `json:"oidc_issuer_url,omitempty"`
	OIDCAudience         string   `json:"oidc_audience,omitempty"`
	OIDCAllowedGroups    []string `json:"oidc_allowed_groups,omitempty"`
	OIDCJWKSCacheTime    int      `json:"oidc_jwks_cache_time,omitempty"`    // seconds
	OIDCSkipIssuerVerify bool     `json:"oidc_skip_issuer_verify,omitempty"` // for testing

	// mTLS auth
	MTLSCACert       string `json:"mtls_ca_cert,omitempty"`
	MTLSVerifyClient bool   `json:"mtls_verify_client,omitempty"`
}
