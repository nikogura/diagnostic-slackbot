package auth

import (
	"errors"
	"net/http"
)

// APIKeyAuth implements API key authentication via X-API-Key header.
type APIKeyAuth struct {
	keys map[string]string // key -> username mapping
}

// NewAPIKeyAuth creates a new API key authenticator.
func NewAPIKeyAuth(keys map[string]string) (auth *APIKeyAuth) {
	auth = &APIKeyAuth{
		keys: keys,
	}
	return auth
}

// Name returns the auth method name.
func (a *APIKeyAuth) Name() (name string) {
	name = "api-key"
	return name
}

// Authenticate validates the API key.
func (a *APIKeyAuth) Authenticate(r *http.Request) (result *Result, err error) {
	//nolint:canonicalheader // X-API-Key is industry standard, not X-Api-Key
	apiKey := r.Header.Get("X-API-Key")
	if apiKey == "" {
		err = errors.New("missing X-API-Key header")
		return result, err
	}

	username, exists := a.keys[apiKey]
	if !exists {
		err = errors.New("invalid API key")
		return result, err
	}

	result = &Result{
		Authenticated: true,
		Method:        a.Name(),
		Username:      username,
	}
	return result, err
}
