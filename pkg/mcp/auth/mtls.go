package auth

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
)

// MTLSAuth implements mutual TLS authentication.
type MTLSAuth struct {
	caPool       *x509.CertPool
	verifyClient bool
}

// MTLSConfig holds mTLS configuration.
type MTLSConfig struct {
	CACertPath   string
	VerifyClient bool
}

// NewMTLSAuth creates a new mTLS authenticator.
func NewMTLSAuth(config *MTLSConfig) (auth *MTLSAuth, err error) {
	auth = &MTLSAuth{
		verifyClient: config.VerifyClient,
	}

	// Load CA certificate if provided
	if config.CACertPath != "" {
		var caCert []byte
		caCert, err = os.ReadFile(config.CACertPath)
		if err != nil {
			err = fmt.Errorf("failed to read CA certificate: %w", err)
			return auth, err
		}

		auth.caPool = x509.NewCertPool()
		if !auth.caPool.AppendCertsFromPEM(caCert) {
			err = errors.New("failed to parse CA certificate")
			return auth, err
		}
	}

	return auth, err
}

// Name returns the auth method name.
func (a *MTLSAuth) Name() (name string) {
	name = "mtls"
	return name
}

// Authenticate validates the client certificate.
func (a *MTLSAuth) Authenticate(r *http.Request) (result *Result, err error) {
	if r.TLS == nil {
		err = errors.New("no TLS connection")
		return result, err
	}

	if len(r.TLS.PeerCertificates) == 0 {
		err = errors.New("no client certificate provided")
		return result, err
	}

	clientCert := r.TLS.PeerCertificates[0]

	// Verify certificate if CA pool is configured
	if a.caPool != nil && a.verifyClient {
		opts := x509.VerifyOptions{
			Roots:     a.caPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

		_, verifyErr := clientCert.Verify(opts)
		if verifyErr != nil {
			err = fmt.Errorf("certificate verification failed: %w", verifyErr)
			return result, err
		}
	}

	// Extract identity from certificate
	username := clientCert.Subject.CommonName
	if username == "" && len(clientCert.DNSNames) > 0 {
		username = clientCert.DNSNames[0]
	}
	if username == "" {
		username = clientCert.Subject.String()
	}

	result = &Result{
		Authenticated: true,
		Method:        a.Name(),
		Username:      username,
		Subject:       clientCert.Subject.String(),
	}

	// Extract email from SAN if present
	if len(clientCert.EmailAddresses) > 0 {
		result.Email = clientCert.EmailAddresses[0]
	}

	return result, err
}

// GetTLSConfig returns a TLS config for server with client cert requirements.
func (a *MTLSAuth) GetTLSConfig() (config *tls.Config) {
	config = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if a.verifyClient {
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = a.caPool
	} else {
		config.ClientAuth = tls.RequestClientCert
	}

	return config
}
