package mcp

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewGrafanaClient(t *testing.T) {
	// Cannot run in parallel due to shared logger

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	tests := []struct {
		name      string
		baseURL   string
		apiKey    string
		expectErr bool
		errorMsg  string
	}{
		{
			name:      "valid_config",
			baseURL:   "http://grafana.example.com",
			apiKey:    "test-api-key",
			expectErr: false,
		},
		{
			name:      "missing_base_url",
			baseURL:   "",
			apiKey:    "test-api-key",
			expectErr: true,
			errorMsg:  "base URL is required",
		},
		{
			name:      "missing_api_key",
			baseURL:   "http://grafana.example.com",
			apiKey:    "",
			expectErr: true,
			errorMsg:  "API key is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Cannot run in parallel due to shared resources

			client, err := NewGrafanaClient(tt.baseURL, tt.apiKey, logger)

			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorMsg)
				assert.Nil(t, client)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, client)
				assert.Equal(t, tt.baseURL, client.baseURL)
				assert.Equal(t, tt.apiKey, client.apiKey)
			}
		})
	}
}

func TestGrafanaClientListDashboards(t *testing.T) {
	// Cannot run in parallel due to shared resources

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctx := context.Background()

	tests := []struct {
		name           string
		serverResponse string
		serverStatus   int
		expectErr      bool
		expectedCount  int
	}{
		{
			name: "successful_list",
			serverResponse: `[
				{"id": 1, "uid": "dash1", "title": "Dashboard 1", "type": "dash-db"},
				{"id": 2, "uid": "dash2", "title": "Dashboard 2", "type": "dash-db"}
			]`,
			serverStatus:  http.StatusOK,
			expectErr:     false,
			expectedCount: 2,
		},
		{
			name:           "empty_list",
			serverResponse: `[]`,
			serverStatus:   http.StatusOK,
			expectErr:      false,
			expectedCount:  0,
		},
		{
			name:           "server_error",
			serverResponse: `{"message": "Internal server error"}`,
			serverStatus:   http.StatusInternalServerError,
			expectErr:      true,
		},
		{
			name:           "invalid_json",
			serverResponse: `invalid json`,
			serverStatus:   http.StatusOK,
			expectErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Cannot run in parallel due to shared resources

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/api/search", r.URL.Path)
				assert.Equal(t, "type=dash-db", r.URL.RawQuery)
				assert.Equal(t, "Bearer test-api-key", r.Header.Get("Authorization"))

				w.WriteHeader(tt.serverStatus)
				_, _ = w.Write([]byte(tt.serverResponse))
			}))
			t.Cleanup(server.Close)

			client, err := NewGrafanaClient(server.URL, "test-api-key", logger)
			require.NoError(t, err)

			dashboards, err := client.ListDashboards(ctx)

			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Len(t, dashboards, tt.expectedCount)
			}
		})
	}
}

func TestGrafanaClientGetDashboard(t *testing.T) {
	// Cannot run in parallel due to shared resources

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctx := context.Background()

	tests := []struct {
		name           string
		uid            string
		serverResponse string
		serverStatus   int
		expectErr      bool
		expectedTitle  string
	}{
		{
			name: "successful_get",
			uid:  "test-uid",
			serverResponse: `{
				"dashboard": {
					"uid": "test-uid",
					"title": "Test Dashboard",
					"version": 1,
					"panels": []
				},
				"meta": {
					"version": 1,
					"slug": "test-dashboard"
				}
			}`,
			serverStatus:  http.StatusOK,
			expectErr:     false,
			expectedTitle: "Test Dashboard",
		},
		{
			name:           "dashboard_not_found",
			uid:            "nonexistent",
			serverResponse: `{"message": "Dashboard not found"}`,
			serverStatus:   http.StatusNotFound,
			expectErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Cannot run in parallel due to shared resources

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectedPath := "/api/dashboards/uid/" + tt.uid
				assert.Equal(t, expectedPath, r.URL.Path)

				w.WriteHeader(tt.serverStatus)
				_, _ = w.Write([]byte(tt.serverResponse))
			}))
			t.Cleanup(server.Close)

			client, err := NewGrafanaClient(server.URL, "test-api-key", logger)
			require.NoError(t, err)

			dashboard, err := client.GetDashboard(ctx, tt.uid)

			if tt.expectErr {
				require.Error(t, err)
				assert.Nil(t, dashboard)
			} else {
				require.NoError(t, err)
				require.NotNil(t, dashboard)
				assert.Equal(t, tt.expectedTitle, dashboard.Title)
			}
		})
	}
}

func TestGrafanaClientCreateDashboard(t *testing.T) {
	// Cannot run in parallel due to shared resources

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctx := context.Background()

	dashboard := &Dashboard{
		Title: "New Dashboard",
		Tags:  []string{"test"},
		Panels: []Panel{
			{
				ID:    1,
				Type:  "stat",
				Title: "Test Panel",
			},
		},
	}

	tests := []struct {
		name           string
		serverResponse string
		serverStatus   int
		expectErr      bool
		expectedUID    string
	}{
		{
			name: "successful_create",
			serverResponse: `{
				"id": 123,
				"uid": "new-dash-uid",
				"url": "/d/new-dash-uid/new-dashboard",
				"status": "success",
				"version": 1
			}`,
			serverStatus: http.StatusOK,
			expectErr:    false,
			expectedUID:  "new-dash-uid",
		},
		{
			name:           "permission_denied",
			serverResponse: `{"message": "Permission denied"}`,
			serverStatus:   http.StatusForbidden,
			expectErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Cannot run in parallel due to shared resources

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/api/dashboards/db", r.URL.Path)
				assert.Equal(t, http.MethodPost, r.Method)

				// Verify request body
				var req DashboardSaveRequest
				err := json.NewDecoder(r.Body).Decode(&req)
				assert.NoError(t, err)
				assert.Equal(t, dashboard.Title, req.Dashboard.Title)
				assert.False(t, req.Overwrite)

				w.WriteHeader(tt.serverStatus)
				_, _ = w.Write([]byte(tt.serverResponse))
			}))
			t.Cleanup(server.Close)

			client, err := NewGrafanaClient(server.URL, "test-api-key", logger)
			require.NoError(t, err)

			uid, err := client.CreateDashboard(ctx, dashboard, "", "Test message")

			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedUID, uid)
			}
		})
	}
}

func TestGrafanaClientDeleteDashboard(t *testing.T) {
	// Cannot run in parallel due to shared resources

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctx := context.Background()

	tests := []struct {
		name         string
		uid          string
		serverStatus int
		expectErr    bool
	}{
		{
			name:         "successful_delete",
			uid:          "test-uid",
			serverStatus: http.StatusOK,
			expectErr:    false,
		},
		{
			name:         "dashboard_not_found",
			uid:          "nonexistent",
			serverStatus: http.StatusNotFound,
			expectErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Cannot run in parallel due to shared resources

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				expectedPath := "/api/dashboards/uid/" + tt.uid
				assert.Equal(t, expectedPath, r.URL.Path)
				assert.Equal(t, http.MethodDelete, r.Method)

				w.WriteHeader(tt.serverStatus)
				if tt.serverStatus != http.StatusOK {
					_, _ = w.Write([]byte(`{"message": "Error"}`))
				}
			}))
			t.Cleanup(server.Close)

			client, err := NewGrafanaClient(server.URL, "test-api-key", logger)
			require.NoError(t, err)

			err = client.DeleteDashboard(ctx, tt.uid)

			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestGrafanaClientCreateDashboardFromSQL(t *testing.T) {
	// Cannot run in parallel due to shared resources

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctx := context.Background()

	queries := []SQLPanelConfig{
		{
			Title:       "User Count",
			SQL:         "SELECT COUNT(*) FROM users",
			PanelType:   "stat",
			Description: "Total number of users",
		},
		{
			Title:     "Daily Signups",
			SQL:       "SELECT date_trunc('day', created_at) as time, COUNT(*) FROM users GROUP BY 1 ORDER BY 1",
			PanelType: "timeseries",
		},
		{
			Title:     "Top Users",
			SQL:       "SELECT name, email FROM users ORDER BY created_at DESC LIMIT 10",
			PanelType: "table",
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/dashboards/db", r.URL.Path)

		var req DashboardSaveRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		assert.NoError(t, err)

		// Verify dashboard structure
		assert.Equal(t, "Test Dashboard", req.Dashboard.Title)
		assert.Len(t, req.Dashboard.Panels, 3)
		assert.Contains(t, req.Dashboard.Tags, "auto-generated")
		assert.Contains(t, req.Dashboard.Tags, "sql")

		// Check first panel (stat)
		statPanel := req.Dashboard.Panels[0]
		assert.Equal(t, "stat", statPanel.Type)
		assert.Equal(t, "User Count", statPanel.Title)
		assert.Equal(t, 1, statPanel.ID)
		assert.Equal(t, "SELECT COUNT(*) FROM users", statPanel.Targets[0].RawSQL)

		// Check grid positioning
		assert.Equal(t, 0, statPanel.GridPos.X)
		assert.Equal(t, 0, statPanel.GridPos.Y)
		assert.Equal(t, 12, statPanel.GridPos.W)
		assert.Equal(t, 8, statPanel.GridPos.H)

		// Second panel should be next to first
		timeseriesPanel := req.Dashboard.Panels[1]
		assert.Equal(t, 12, timeseriesPanel.GridPos.X)
		assert.Equal(t, 0, timeseriesPanel.GridPos.Y)

		// Third panel should be on new row
		tablePanel := req.Dashboard.Panels[2]
		assert.Equal(t, 0, tablePanel.GridPos.X)
		assert.Equal(t, 8, tablePanel.GridPos.Y)

		response := `{
			"id": 456,
			"uid": "sql-dashboard-uid",
			"url": "/d/sql-dashboard-uid/test-dashboard",
			"status": "success"
		}`
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(server.Close)

	client, err := NewGrafanaClient(server.URL, "test-api-key", logger)
	require.NoError(t, err)

	uid, err := client.CreateDashboardFromSQL(ctx, "Test Dashboard", queries, "postgres-uid")
	require.NoError(t, err)
	assert.Equal(t, "sql-dashboard-uid", uid)
}

func TestGrafanaClientCreateDashboardFromQueries(t *testing.T) {
	// Cannot run in parallel due to shared resources

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	ctx := context.Background()

	queries := []PanelQueryConfig{
		{
			Title:          "Database Connections",
			Query:          "SELECT COUNT(*) FROM pg_stat_activity",
			PanelType:      "stat",
			DatasourceType: "postgres",
			DatasourceUID:  "postgres-uid",
		},
		{
			Title:          "CPU Usage",
			Query:          "rate(node_cpu_seconds_total[5m])",
			PanelType:      "timeseries",
			DatasourceType: "prometheus",
			DatasourceUID:  "prometheus-uid",
			Legend:         "{{instance}}",
		},
		{
			Title:          "EC2 CPU Utilization",
			Query:          "",
			PanelType:      "timeseries",
			DatasourceType: "cloudwatch",
			DatasourceUID:  "cloudwatch-uid",
			Region:         "us-east-1",
			Namespace:      "AWS/EC2",
			MetricName:     "CPUUtilization",
			Statistics:     []string{"Average", "Maximum"},
			Dimensions: map[string]string{
				"InstanceId": "i-1234567890abcdef0",
			},
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/api/dashboards/db", r.URL.Path)

		var req DashboardSaveRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		assert.NoError(t, err)

		// Verify dashboard structure
		assert.Equal(t, "Multi-Datasource Dashboard", req.Dashboard.Title)
		assert.Len(t, req.Dashboard.Panels, 3)
		assert.Contains(t, req.Dashboard.Tags, "auto-generated")

		// Check PostgreSQL panel
		postgresPanel := req.Dashboard.Panels[0]
		assert.Equal(t, "stat", postgresPanel.Type)
		assert.Equal(t, "Database Connections", postgresPanel.Title)
		assert.Equal(t, "SELECT COUNT(*) FROM pg_stat_activity", postgresPanel.Targets[0].RawSQL)
		assert.Equal(t, "postgres-uid", postgresPanel.Datasource["uid"])

		// Check Prometheus panel
		promPanel := req.Dashboard.Panels[1]
		assert.Equal(t, "timeseries", promPanel.Type)
		assert.Equal(t, "CPU Usage", promPanel.Title)
		assert.Equal(t, "rate(node_cpu_seconds_total[5m])", promPanel.Targets[0].Expr)
		assert.Equal(t, "prometheus-uid", promPanel.Datasource["uid"])

		// Check CloudWatch panel
		cwPanel := req.Dashboard.Panels[2]
		assert.Equal(t, "timeseries", cwPanel.Type)
		assert.Equal(t, "EC2 CPU Utilization", cwPanel.Title)
		assert.Equal(t, "cloudwatch-uid", cwPanel.Datasource["uid"])

		response := `{
			"id": 789,
			"uid": "multi-datasource-uid",
			"url": "/d/multi-datasource-uid/multi-datasource-dashboard",
			"status": "success"
		}`
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(response))
	}))
	t.Cleanup(server.Close)

	client, err := NewGrafanaClient(server.URL, "test-api-key", logger)
	require.NoError(t, err)

	uid, err := client.CreateDashboardFromQueries(ctx, "Multi-Datasource Dashboard", queries)
	require.NoError(t, err)
	assert.Equal(t, "multi-datasource-uid", uid)
}
