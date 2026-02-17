package auth

import (
	"errors"
	"net/http"
	"strings"
)

// StaticTokenAuth implements simple bearer token authentication.
type StaticTokenAuth struct {
	token string
}

// NewStaticTokenAuth creates a new static token authenticator.
func NewStaticTokenAuth(token string) (auth *StaticTokenAuth) {
	auth = &StaticTokenAuth{
		token: token,
	}
	return auth
}

// Name returns the auth method name.
func (a *StaticTokenAuth) Name() (name string) {
	name = "static-bearer"
	return name
}

// Authenticate validates the static bearer token.
func (a *StaticTokenAuth) Authenticate(r *http.Request) (result *Result, err error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		err = errors.New("missing Authorization header")
		return result, err
	}

	// Check for Bearer token format
	const bearerPrefix = "Bearer "
	if len(authHeader) < len(bearerPrefix) || authHeader[:len(bearerPrefix)] != bearerPrefix {
		err = errors.New("invalid Authorization header format (expected: Bearer <token>)")
		return result, err
	}

	token := authHeader[len(bearerPrefix):]
	if token != a.token {
		err = errors.New("invalid token")
		return result, err
	}

	result = &Result{
		Authenticated: true,
		Method:        a.Name(),
		Username:      "static-token-user",
	}
	return result, err
}

// extractBearerToken is a helper to extract bearer token from Authorization header.
func extractBearerToken(r *http.Request) (token string, err error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		err = errors.New("missing Authorization header")
		return token, err
	}

	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		err = errors.New("invalid Authorization header format (expected: Bearer <token>)")
		return token, err
	}

	token = strings.TrimSpace(parts[1])
	return token, err
}
