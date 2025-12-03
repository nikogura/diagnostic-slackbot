package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server provides HTTP endpoints for health checks and metrics.
type Server struct {
	Address string
	Logger  *slog.Logger
}

// NewServer creates a new metrics server.
func NewServer(address string, logger *slog.Logger) (result *Server) {
	result = &Server{
		Address: address,
		Logger:  logger,
	}

	return result
}

// Start starts the metrics server.
func (s *Server) Start(ctx context.Context) (err error) {
	mux := http.NewServeMux()

	mux.HandleFunc("/healthz", s.LivenessHandler)
	mux.HandleFunc("/readyz", s.ReadinessHandler)
	mux.Handle("/metrics", promhttp.Handler())

	server := &http.Server{
		Addr:    s.Address,
		Handler: mux,
	}

	// Start server in goroutine
	go func() {
		s.Logger.InfoContext(ctx, "starting metrics server", slog.String("address", s.Address))

		startErr := server.ListenAndServe()
		if startErr != nil && startErr != http.ErrServerClosed {
			s.Logger.ErrorContext(ctx, "metrics server error", slog.String("error", startErr.Error()))
		}
	}()

	// Wait for context cancellation
	<-ctx.Done()

	s.Logger.InfoContext(ctx, "shutting down metrics server")

	err = server.Shutdown(context.Background())
	if err != nil {
		err = fmt.Errorf("shutting down metrics server: %w", err)
		return err
	}

	return err
}

// LivenessHandler handles liveness probe requests.
func (s *Server) LivenessHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// ReadinessHandler handles readiness probe requests.
func (s *Server) ReadinessHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}
