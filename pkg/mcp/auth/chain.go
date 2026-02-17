package auth

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
)

// Chain tries multiple authentication methods in order.
type Chain struct {
	methods []Method
	logger  *slog.Logger
}

// NewChain creates a new authentication chain.
func NewChain(methods []Method, logger *slog.Logger) (chain *Chain) {
	chain = &Chain{
		methods: methods,
		logger:  logger,
	}
	return chain
}

// Authenticate tries each auth method in order until one succeeds.
func (c *Chain) Authenticate(r *http.Request) (result *Result, err error) {
	if len(c.methods) == 0 {
		// No auth configured - allow all
		result = &Result{
			Authenticated: true,
			Method:        "none",
			Username:      "anonymous",
		}
		return result, err
	}

	var lastErr error
	for _, method := range c.methods {
		result, err = method.Authenticate(r)
		if err == nil {
			c.logger.Debug("Authentication succeeded",
				slog.String("method", method.Name()),
				slog.String("username", result.Username))
			//nolint:nilerr // err is nil here, which is correct for successful auth
			return result, err
		}
		lastErr = err
		c.logger.Debug("Authentication failed",
			slog.String("method", method.Name()),
			slog.String("error", err.Error()))
	}

	if lastErr != nil {
		err = fmt.Errorf("all authentication methods failed: %w", lastErr)
		return result, err
	}

	err = errors.New("authentication failed: no methods succeeded")
	return result, err
}

// Name returns the chain name.
func (c *Chain) Name() (name string) {
	name = "auth-chain"
	return name
}
