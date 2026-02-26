package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// graphqlTokenRefreshBuffer is how early to refresh a token before its actual expiry.
const graphqlTokenRefreshBuffer = 5 * time.Minute

// GraphQLOAuth2Config holds OAuth2 client credentials configuration.
type GraphQLOAuth2Config struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	Audience     string
}

// graphqlTokenCache holds a cached OAuth2 access token and its expiry.
type graphqlTokenCache struct {
	token  string
	expiry time.Time
}

// oAuth2TokenResponse represents the JSON response from an OAuth2 token endpoint.
type oAuth2TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// ensureAuth refreshes the OAuth2 token if configured and the cached token has expired.
// It is a no-op when oauth2Config is nil (static token mode).
func (c *GraphQLClient) ensureAuth(ctx context.Context) (err error) {
	if c.oauth2Config == nil {
		return err
	}

	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	if c.tokenCache != nil && time.Now().Before(c.tokenCache.expiry) {
		return err
	}

	err = c.fetchOAuth2Token(ctx)

	return err
}

// fetchOAuth2Token exchanges client credentials for an access token and caches it.
// Must be called with tokenMu held.
func (c *GraphQLClient) fetchOAuth2Token(ctx context.Context) (err error) {
	formData := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.oauth2Config.ClientID},
		"client_secret": {c.oauth2Config.ClientSecret},
	}

	if c.oauth2Config.Audience != "" {
		formData.Set("audience", c.oauth2Config.Audience)
	}

	var req *http.Request
	req, err = http.NewRequestWithContext(ctx, http.MethodPost, c.oauth2Config.TokenURL, strings.NewReader(formData.Encode()))
	if err != nil {
		err = fmt.Errorf("creating oauth2 token request: %w", err)
		return err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var resp *http.Response
	resp, err = c.httpClient.Do(req)
	if err != nil {
		err = fmt.Errorf("executing oauth2 token request: %w", err)
		return err
	}
	defer resp.Body.Close()

	var body []byte
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("reading oauth2 token response: %w", err)
		return err
	}

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("oauth2 token request failed (status %d): %s", resp.StatusCode, string(body))
		return err
	}

	var tokenResp oAuth2TokenResponse
	err = json.Unmarshal(body, &tokenResp)
	if err != nil {
		err = fmt.Errorf("parsing oauth2 token response: %w", err)
		return err
	}

	if tokenResp.AccessToken == "" {
		err = errors.New("oauth2 token response missing access_token")
		return err
	}

	expiry := time.Now().Add(time.Duration(tokenResp.ExpiresIn)*time.Second - graphqlTokenRefreshBuffer)

	c.tokenCache = &graphqlTokenCache{
		token:  tokenResp.AccessToken,
		expiry: expiry,
	}

	c.headers["Authorization"] = "Bearer " + tokenResp.AccessToken

	c.logger.InfoContext(ctx, "OAuth2 token refreshed",
		slog.String("endpoint", c.name),
		slog.Time("expiry", expiry))

	return err
}

// collectGraphQLOAuth2Config reads OAuth2 env vars for the given endpoint name.
// For the default endpoint (name=""), it looks for GRAPHQL_AUTH_URL, etc.
// Returns nil if the required vars (AUTH_URL, CLIENT_ID, CLIENT_SECRET) are not all set.
func collectGraphQLOAuth2Config(name string, logger *slog.Logger) (config *GraphQLOAuth2Config) {
	var authURLKey, clientIDKey, clientSecretKey, audienceKey string

	if name == "" {
		authURLKey = "GRAPHQL_AUTH_URL"
		clientIDKey = "GRAPHQL_CLIENT_ID"
		clientSecretKey = "GRAPHQL_CLIENT_SECRET"
		audienceKey = "GRAPHQL_AUDIENCE"
	} else {
		upperName := strings.ToUpper(name)
		authURLKey = fmt.Sprintf("GRAPHQL_%s_AUTH_URL", upperName)
		clientIDKey = fmt.Sprintf("GRAPHQL_%s_CLIENT_ID", upperName)
		clientSecretKey = fmt.Sprintf("GRAPHQL_%s_CLIENT_SECRET", upperName)
		audienceKey = fmt.Sprintf("GRAPHQL_%s_AUDIENCE", upperName)
	}

	authURL := os.Getenv(authURLKey)
	clientID := os.Getenv(clientIDKey)
	clientSecret := os.Getenv(clientSecretKey)

	if authURL == "" || clientID == "" || clientSecret == "" {
		return config
	}

	audience := os.Getenv(audienceKey)

	logger.Debug("Found GraphQL OAuth2 configuration",
		slog.String("auth_url_key", authURLKey),
		slog.String("client_id_key", clientIDKey),
		slog.Bool("has_audience", audience != ""))

	config = &GraphQLOAuth2Config{
		TokenURL:     authURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Audience:     audience,
	}

	return config
}
