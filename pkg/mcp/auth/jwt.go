package auth

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// JWTAuth implements JWT bearer token authentication.
type JWTAuth struct {
	secret    []byte
	algorithm string
}

// JWTConfig holds JWT configuration.
type JWTConfig struct {
	Secret    []byte
	Algorithm string
}

// NewJWTAuth creates a new JWT authenticator.
func NewJWTAuth(config *JWTConfig) (auth *JWTAuth, err error) {
	if len(config.Secret) == 0 {
		err = errors.New("JWT secret is required")
		return auth, err
	}

	algorithm := config.Algorithm
	if algorithm == "" {
		algorithm = "HS256" // Default to HS256
	}

	auth = &JWTAuth{
		secret:    config.Secret,
		algorithm: algorithm,
	}
	return auth, err
}

// Name returns the auth method name.
func (a *JWTAuth) Name() (name string) {
	name = "jwt"
	return name
}

// Authenticate validates the JWT token.
//
//nolint:gocognit // JWT validation requires multiple validation steps
func (a *JWTAuth) Authenticate(r *http.Request) (result *Result, err error) {
	var tokenString string
	tokenString, err = extractBearerToken(r)
	if err != nil {
		return result, err
	}

	// Parse and validate token
	var token *jwt.Token
	token, err = jwt.Parse(tokenString, func(token *jwt.Token) (key interface{}, keyErr error) {
		// Verify signing method matches expected algorithm
		expectedMethod := jwt.GetSigningMethod(a.algorithm)
		if expectedMethod == nil {
			keyErr = fmt.Errorf("unsupported signing algorithm: %s", a.algorithm)
			return key, keyErr
		}

		if token.Method.Alg() != expectedMethod.Alg() {
			keyErr = fmt.Errorf("unexpected signing method: %v (expected: %s)", token.Header["alg"], a.algorithm)
			return key, keyErr
		}

		key = a.secret
		return key, keyErr
	})

	if err != nil {
		err = fmt.Errorf("token validation failed: %w", err)
		return result, err
	}

	if !token.Valid {
		err = errors.New("token is invalid")
		return result, err
	}

	// Extract standard claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		err = errors.New("invalid token claims format")
		return result, err
	}

	// Validate expiration
	if exp, expOK := claims["exp"].(float64); expOK {
		if time.Unix(int64(exp), 0).Before(time.Now()) {
			err = errors.New("token has expired")
			return result, err
		}
	}

	// Extract user information
	result = &Result{
		Authenticated: true,
		Method:        a.Name(),
	}

	if sub, subOK := claims["sub"].(string); subOK {
		result.Subject = sub
		result.Username = sub // Use subject as username by default
	}

	if username, usernameOK := claims["username"].(string); usernameOK {
		result.Username = username
	}

	if email, emailOK := claims["email"].(string); emailOK {
		result.Email = email
	}

	// Extract groups if present
	if groupsRaw, groupsOK := claims["groups"]; groupsOK {
		switch groups := groupsRaw.(type) {
		case []string:
			result.Groups = groups
		case []interface{}:
			for _, g := range groups {
				if groupStr, groupStrOK := g.(string); groupStrOK {
					result.Groups = append(result.Groups, groupStr)
				}
			}
		}
	}

	return result, err
}
