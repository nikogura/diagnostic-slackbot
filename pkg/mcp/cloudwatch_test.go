package mcp

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockCloudWatchLogsClient implements CloudWatchLogsClient for testing.
type mockCloudWatchLogsClient struct {
	startQueryFunc        func(ctx context.Context, params *cloudwatchlogs.StartQueryInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.StartQueryOutput, error)
	getQueryResultsFunc   func(ctx context.Context, params *cloudwatchlogs.GetQueryResultsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetQueryResultsOutput, error)
	describeLogGroupsFunc func(ctx context.Context, params *cloudwatchlogs.DescribeLogGroupsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.DescribeLogGroupsOutput, error)
	getLogEventsFunc      func(ctx context.Context, params *cloudwatchlogs.GetLogEventsInput, optFns ...func(*cloudwatchlogs.Options)) (*cloudwatchlogs.GetLogEventsOutput, error)
}

func (m *mockCloudWatchLogsClient) StartQuery(ctx context.Context, params *cloudwatchlogs.StartQueryInput, optFns ...func(*cloudwatchlogs.Options)) (result *cloudwatchlogs.StartQueryOutput, err error) {
	if m.startQueryFunc != nil {
		result, err = m.startQueryFunc(ctx, params, optFns...)
		return result, err
	}
	err = errors.New("startQueryFunc not implemented")
	return result, err
}

func (m *mockCloudWatchLogsClient) GetQueryResults(ctx context.Context, params *cloudwatchlogs.GetQueryResultsInput, optFns ...func(*cloudwatchlogs.Options)) (result *cloudwatchlogs.GetQueryResultsOutput, err error) {
	if m.getQueryResultsFunc != nil {
		result, err = m.getQueryResultsFunc(ctx, params, optFns...)
		return result, err
	}
	err = errors.New("getQueryResultsFunc not implemented")
	return result, err
}

func (m *mockCloudWatchLogsClient) DescribeLogGroups(ctx context.Context, params *cloudwatchlogs.DescribeLogGroupsInput, optFns ...func(*cloudwatchlogs.Options)) (result *cloudwatchlogs.DescribeLogGroupsOutput, err error) {
	if m.describeLogGroupsFunc != nil {
		result, err = m.describeLogGroupsFunc(ctx, params, optFns...)
		return result, err
	}
	err = errors.New("describeLogGroupsFunc not implemented")
	return result, err
}

func (m *mockCloudWatchLogsClient) GetLogEvents(ctx context.Context, params *cloudwatchlogs.GetLogEventsInput, optFns ...func(*cloudwatchlogs.Options)) (result *cloudwatchlogs.GetLogEventsOutput, err error) {
	if m.getLogEventsFunc != nil {
		result, err = m.getLogEventsFunc(ctx, params, optFns...)
		return result, err
	}
	err = errors.New("getLogEventsFunc not implemented")
	return result, err
}

// TestParseLogGroupsArg tests the log groups argument parsing.
func TestParseLogGroupsArg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		args        map[string]interface{}
		expected    []string
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid_single_group",
			args: map[string]interface{}{
				"log_groups": []interface{}{"/aws/lambda/my-function"},
			},
			expected:    []string{"/aws/lambda/my-function"},
			expectError: false,
		},
		{
			name: "valid_multiple_groups",
			args: map[string]interface{}{
				"log_groups": []interface{}{"/aws/lambda/func1", "/aws/lambda/func2", "/ecs/service"},
			},
			expected:    []string{"/aws/lambda/func1", "/aws/lambda/func2", "/ecs/service"},
			expectError: false,
		},
		{
			name:        "missing_log_groups",
			args:        map[string]interface{}{},
			expected:    nil,
			expectError: true,
			errorMsg:    "log_groups parameter is required",
		},
		{
			name: "empty_log_groups",
			args: map[string]interface{}{
				"log_groups": []interface{}{},
			},
			expected:    nil,
			expectError: true,
			errorMsg:    "log_groups parameter is required",
		},
		{
			name: "log_groups_with_empty_strings",
			args: map[string]interface{}{
				"log_groups": []interface{}{"", ""},
			},
			expected:    nil,
			expectError: true,
			errorMsg:    "log_groups must contain at least one valid log group name",
		},
		{
			name: "mixed_valid_and_empty",
			args: map[string]interface{}{
				"log_groups": []interface{}{"/valid/group", "", "/another/valid"},
			},
			expected:    []string{"/valid/group", "/another/valid"},
			expectError: false,
		},
		{
			name: "wrong_type",
			args: map[string]interface{}{
				"log_groups": "not-an-array",
			},
			expected:    nil,
			expectError: true,
			errorMsg:    "log_groups parameter is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := parseLogGroupsArg(tt.args)

			if tt.expectError {
				require.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// TestParseCloudWatchRegionArg tests the region argument parsing.
func TestParseCloudWatchRegionArg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     map[string]interface{}
		expected string
	}{
		{
			name:     "default_region",
			args:     map[string]interface{}{},
			expected: "us-east-1",
		},
		{
			name: "custom_region",
			args: map[string]interface{}{
				"region": "eu-west-1",
			},
			expected: "eu-west-1",
		},
		{
			name: "empty_region",
			args: map[string]interface{}{
				"region": "",
			},
			expected: "us-east-1",
		},
		{
			name: "wrong_type",
			args: map[string]interface{}{
				"region": 123,
			},
			expected: "us-east-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := parseCloudWatchRegionArg(tt.args)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestParseCloudWatchLimitArg tests the limit argument parsing.
func TestParseCloudWatchLimitArg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     map[string]interface{}
		expected int
	}{
		{
			name:     "default_limit",
			args:     map[string]interface{}{},
			expected: 100,
		},
		{
			name: "custom_limit",
			args: map[string]interface{}{
				"limit": float64(500),
			},
			expected: 500,
		},
		{
			name: "exceeds_max_limit",
			args: map[string]interface{}{
				"limit": float64(20000),
			},
			expected: 10000, // Capped at max
		},
		{
			name: "wrong_type",
			args: map[string]interface{}{
				"limit": "500",
			},
			expected: 100, // Falls back to default
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := parseCloudWatchLimitArg(tt.args)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestParseEndTimeArg tests the end_time argument parsing.
func TestParseEndTimeArg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     map[string]interface{}
		expected string
	}{
		{
			name:     "default_now",
			args:     map[string]interface{}{},
			expected: "now",
		},
		{
			name: "explicit_now",
			args: map[string]interface{}{
				"end_time": "now",
			},
			expected: "now",
		},
		{
			name: "custom_time",
			args: map[string]interface{}{
				"end_time": "2024-01-15T12:00:00Z",
			},
			expected: "2024-01-15T12:00:00Z",
		},
		{
			name: "empty_string",
			args: map[string]interface{}{
				"end_time": "",
			},
			expected: "now",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := parseEndTimeArg(tt.args)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestParseTimeArg tests the time argument parsing.
func TestParseTimeArg(t *testing.T) {
	t.Parallel()

	now := time.Now()

	tests := []struct {
		name        string
		input       string
		expectError bool
		validate    func(t *testing.T, result time.Time)
	}{
		{
			name:        "now",
			input:       "now",
			expectError: false,
			validate: func(t *testing.T, result time.Time) {
				t.Helper()
				assert.WithinDuration(t, now, result, time.Second)
			},
		},
		{
			name:        "empty_string",
			input:       "",
			expectError: false,
			validate: func(t *testing.T, result time.Time) {
				t.Helper()
				assert.WithinDuration(t, now, result, time.Second)
			},
		},
		{
			name:        "rfc3339",
			input:       "2024-01-15T12:00:00Z",
			expectError: false,
			validate: func(t *testing.T, result time.Time) {
				t.Helper()
				expected := time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)
				assert.Equal(t, expected, result)
			},
		},
		{
			name:        "relative_hours",
			input:       "1h",
			expectError: false,
			validate: func(t *testing.T, result time.Time) {
				t.Helper()
				expected := now.Add(-1 * time.Hour)
				assert.WithinDuration(t, expected, result, 2*time.Second)
			},
		},
		{
			name:        "relative_days",
			input:       "7d",
			expectError: false,
			validate: func(t *testing.T, result time.Time) {
				t.Helper()
				expected := now.Add(-7 * 24 * time.Hour)
				assert.WithinDuration(t, expected, result, 2*time.Second)
			},
		},
		{
			name:        "relative_minutes",
			input:       "30m",
			expectError: false,
			validate: func(t *testing.T, result time.Time) {
				t.Helper()
				expected := now.Add(-30 * time.Minute)
				assert.WithinDuration(t, expected, result, 2*time.Second)
			},
		},
		{
			name:        "invalid_format",
			input:       "invalid",
			expectError: true,
		},
		{
			name:        "invalid_relative",
			input:       "abc",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := parseTimeArg(tt.input)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.validate != nil {
					tt.validate(t, result)
				}
			}
		})
	}
}

// TestParseRelativeDuration tests the relative duration parsing.
func TestParseRelativeDuration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		expected    time.Duration
		expectError bool
	}{
		{
			name:     "hours",
			input:    "2h",
			expected: 2 * time.Hour,
		},
		{
			name:     "minutes",
			input:    "30m",
			expected: 30 * time.Minute,
		},
		{
			name:     "seconds",
			input:    "90s",
			expected: 90 * time.Second,
		},
		{
			name:     "days",
			input:    "3d",
			expected: 3 * 24 * time.Hour,
		},
		{
			name:     "combined",
			input:    "1h30m",
			expected: 1*time.Hour + 30*time.Minute,
		},
		{
			name:        "empty",
			input:       "",
			expectError: true,
		},
		{
			name:        "invalid",
			input:       "abc",
			expectError: true,
		},
		{
			name:        "invalid_days",
			input:       "xd",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := parseRelativeDuration(tt.input)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

// TestRunCloudWatchQuery tests the CloudWatch query execution.
func TestRunCloudWatchQuery(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	startTime := time.Now().Add(-1 * time.Hour)
	endTime := time.Now()
	logGroups := []string{"/aws/lambda/test-function"}
	query := "fields @timestamp, @message | limit 10"

	t.Run("successful_query", func(t *testing.T) {
		t.Parallel()

		mock := &mockCloudWatchLogsClient{
			startQueryFunc: func(_ context.Context, params *cloudwatchlogs.StartQueryInput, _ ...func(*cloudwatchlogs.Options)) (result *cloudwatchlogs.StartQueryOutput, err error) {
				assert.Equal(t, logGroups, params.LogGroupNames)
				assert.Equal(t, query, aws.ToString(params.QueryString))

				result = &cloudwatchlogs.StartQueryOutput{
					QueryId: aws.String("test-query-id-123"),
				}
				return result, err
			},
			getQueryResultsFunc: func(_ context.Context, params *cloudwatchlogs.GetQueryResultsInput, _ ...func(*cloudwatchlogs.Options)) (result *cloudwatchlogs.GetQueryResultsOutput, err error) {
				assert.Equal(t, "test-query-id-123", aws.ToString(params.QueryId))

				result = &cloudwatchlogs.GetQueryResultsOutput{
					Status: types.QueryStatusComplete,
					Results: [][]types.ResultField{
						{
							{Field: aws.String("@timestamp"), Value: aws.String("2024-01-15 12:00:00.000")},
							{Field: aws.String("@message"), Value: aws.String("Test log message")},
						},
						{
							{Field: aws.String("@timestamp"), Value: aws.String("2024-01-15 12:01:00.000")},
							{Field: aws.String("@message"), Value: aws.String("Another log message")},
						},
					},
					Statistics: &types.QueryStatistics{
						BytesScanned:   1024.0,
						RecordsMatched: 2.0,
						RecordsScanned: 100.0,
					},
				}
				return result, err
			},
		}

		result, err := runCloudWatchQuery(ctx, mock, logGroups, query, startTime, endTime, 100, "us-east-1")

		require.NoError(t, err)
		assert.Equal(t, "test-query-id-123", result.QueryID)
		assert.Equal(t, "Complete", result.Status)
		assert.Equal(t, 2, result.ResultCount)
		assert.Len(t, result.Results, 2)
		assert.Equal(t, "Test log message", result.Results[0]["@message"])
		assert.NotNil(t, result.Statistics)
		assert.InDelta(t, 1024.0, result.Statistics.BytesScanned, 0.001)
	})

	t.Run("query_failed", func(t *testing.T) {
		t.Parallel()

		mock := &mockCloudWatchLogsClient{
			startQueryFunc: func(_ context.Context, _ *cloudwatchlogs.StartQueryInput, _ ...func(*cloudwatchlogs.Options)) (result *cloudwatchlogs.StartQueryOutput, err error) {
				result = &cloudwatchlogs.StartQueryOutput{
					QueryId: aws.String("failed-query-id"),
				}
				return result, err
			},
			getQueryResultsFunc: func(_ context.Context, _ *cloudwatchlogs.GetQueryResultsInput, _ ...func(*cloudwatchlogs.Options)) (result *cloudwatchlogs.GetQueryResultsOutput, err error) {
				result = &cloudwatchlogs.GetQueryResultsOutput{
					Status: types.QueryStatusFailed,
				}
				return result, err
			},
		}

		_, err := runCloudWatchQuery(ctx, mock, logGroups, query, startTime, endTime, 100, "us-east-1")

		require.Error(t, err)
		assert.Contains(t, err.Error(), "Failed")
	})

	t.Run("start_query_error", func(t *testing.T) {
		t.Parallel()

		mock := &mockCloudWatchLogsClient{
			startQueryFunc: func(_ context.Context, _ *cloudwatchlogs.StartQueryInput, _ ...func(*cloudwatchlogs.Options)) (result *cloudwatchlogs.StartQueryOutput, err error) {
				err = errors.New("AWS error: access denied")
				return result, err
			},
		}

		_, err := runCloudWatchQuery(ctx, mock, logGroups, query, startTime, endTime, 100, "us-east-1")

		require.Error(t, err)
		assert.Contains(t, err.Error(), "starting query")
	})

	t.Run("get_results_error", func(t *testing.T) {
		t.Parallel()

		mock := &mockCloudWatchLogsClient{
			startQueryFunc: func(_ context.Context, _ *cloudwatchlogs.StartQueryInput, _ ...func(*cloudwatchlogs.Options)) (result *cloudwatchlogs.StartQueryOutput, err error) {
				result = &cloudwatchlogs.StartQueryOutput{
					QueryId: aws.String("error-query-id"),
				}
				return result, err
			},
			getQueryResultsFunc: func(_ context.Context, _ *cloudwatchlogs.GetQueryResultsInput, _ ...func(*cloudwatchlogs.Options)) (result *cloudwatchlogs.GetQueryResultsOutput, err error) {
				err = errors.New("AWS error: query not found")
				return result, err
			},
		}

		_, err := runCloudWatchQuery(ctx, mock, logGroups, query, startTime, endTime, 100, "us-east-1")

		require.Error(t, err)
		assert.Contains(t, err.Error(), "getting query results")
	})
}

// TestListLogGroups tests the log group listing.
func TestListLogGroups(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("successful_list", func(t *testing.T) {
		t.Parallel()

		creationTime := time.Now().Add(-24 * time.Hour).UnixMilli()
		retentionDays := int32(30)

		mock := &mockCloudWatchLogsClient{
			describeLogGroupsFunc: func(_ context.Context, params *cloudwatchlogs.DescribeLogGroupsInput, _ ...func(*cloudwatchlogs.Options)) (result *cloudwatchlogs.DescribeLogGroupsOutput, err error) {
				result = &cloudwatchlogs.DescribeLogGroupsOutput{
					LogGroups: []types.LogGroup{
						{
							LogGroupName:      aws.String("/aws/lambda/func1"),
							Arn:               aws.String("arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/func1:*"),
							CreationTime:      aws.Int64(creationTime),
							StoredBytes:       aws.Int64(1024000),
							RetentionInDays:   &retentionDays,
							MetricFilterCount: aws.Int32(2),
						},
						{
							LogGroupName:      aws.String("/aws/lambda/func2"),
							Arn:               aws.String("arn:aws:logs:us-east-1:123456789012:log-group:/aws/lambda/func2:*"),
							StoredBytes:       aws.Int64(512000),
							MetricFilterCount: aws.Int32(0),
						},
					},
				}
				return result, err
			},
		}

		logGroups, err := listLogGroups(ctx, mock, "", 50)

		require.NoError(t, err)
		assert.Len(t, logGroups, 2)
		assert.Equal(t, "/aws/lambda/func1", logGroups[0].Name)
		assert.Equal(t, int64(1024000), logGroups[0].StoredBytes)
		assert.Equal(t, int32(30), logGroups[0].RetentionDays)
		assert.Equal(t, int32(2), logGroups[0].MetricFilterCount)
		assert.Equal(t, "/aws/lambda/func2", logGroups[1].Name)
	})

	t.Run("with_prefix", func(t *testing.T) {
		t.Parallel()

		mock := &mockCloudWatchLogsClient{
			describeLogGroupsFunc: func(_ context.Context, params *cloudwatchlogs.DescribeLogGroupsInput, _ ...func(*cloudwatchlogs.Options)) (result *cloudwatchlogs.DescribeLogGroupsOutput, err error) {
				assert.Equal(t, "/aws/lambda/", aws.ToString(params.LogGroupNamePrefix))

				result = &cloudwatchlogs.DescribeLogGroupsOutput{
					LogGroups: []types.LogGroup{
						{
							LogGroupName: aws.String("/aws/lambda/func1"),
							StoredBytes:  aws.Int64(1024),
						},
					},
				}
				return result, err
			},
		}

		logGroups, err := listLogGroups(ctx, mock, "/aws/lambda/", 50)

		require.NoError(t, err)
		assert.Len(t, logGroups, 1)
	})

	t.Run("pagination", func(t *testing.T) {
		t.Parallel()

		callCount := 0

		mock := &mockCloudWatchLogsClient{
			describeLogGroupsFunc: func(_ context.Context, params *cloudwatchlogs.DescribeLogGroupsInput, _ ...func(*cloudwatchlogs.Options)) (result *cloudwatchlogs.DescribeLogGroupsOutput, err error) {
				callCount++

				if callCount == 1 {
					result = &cloudwatchlogs.DescribeLogGroupsOutput{
						LogGroups: []types.LogGroup{
							{LogGroupName: aws.String("/group1"), StoredBytes: aws.Int64(100)},
							{LogGroupName: aws.String("/group2"), StoredBytes: aws.Int64(200)},
						},
						NextToken: aws.String("token123"),
					}
					return result, err
				}

				result = &cloudwatchlogs.DescribeLogGroupsOutput{
					LogGroups: []types.LogGroup{
						{LogGroupName: aws.String("/group3"), StoredBytes: aws.Int64(300)},
					},
				}
				return result, err
			},
		}

		logGroups, err := listLogGroups(ctx, mock, "", 50)

		require.NoError(t, err)
		assert.Len(t, logGroups, 3)
		assert.Equal(t, 2, callCount)
	})

	t.Run("error", func(t *testing.T) {
		t.Parallel()

		mock := &mockCloudWatchLogsClient{
			describeLogGroupsFunc: func(_ context.Context, _ *cloudwatchlogs.DescribeLogGroupsInput, _ ...func(*cloudwatchlogs.Options)) (result *cloudwatchlogs.DescribeLogGroupsOutput, err error) {
				err = errors.New("AWS error: access denied")
				return result, err
			},
		}

		_, err := listLogGroups(ctx, mock, "", 50)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "describing log groups")
	})
}

// TestGetLogEvents tests the log events retrieval.
func TestGetLogEvents(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("successful_get", func(t *testing.T) {
		t.Parallel()

		timestamp := time.Now().UnixMilli()
		ingestionTime := time.Now().Add(1 * time.Second).UnixMilli()

		mock := &mockCloudWatchLogsClient{
			getLogEventsFunc: func(_ context.Context, params *cloudwatchlogs.GetLogEventsInput, _ ...func(*cloudwatchlogs.Options)) (result *cloudwatchlogs.GetLogEventsOutput, err error) {
				assert.Equal(t, "/aws/lambda/test", aws.ToString(params.LogGroupName))
				assert.Equal(t, "stream-123", aws.ToString(params.LogStreamName))

				result = &cloudwatchlogs.GetLogEventsOutput{
					Events: []types.OutputLogEvent{
						{
							Timestamp:     aws.Int64(timestamp),
							Message:       aws.String("First log message"),
							IngestionTime: aws.Int64(ingestionTime),
						},
						{
							Timestamp: aws.Int64(timestamp + 1000),
							Message:   aws.String("Second log message"),
						},
					},
				}
				return result, err
			},
		}

		events, err := getLogEvents(ctx, mock, "/aws/lambda/test", "stream-123", nil, nil, 100)

		require.NoError(t, err)
		assert.Len(t, events, 2)
		assert.Equal(t, "First log message", events[0].Message)
		assert.NotEmpty(t, events[0].Timestamp)
		assert.NotEmpty(t, events[0].IngestionTime)
		assert.Equal(t, "Second log message", events[1].Message)
	})

	t.Run("with_time_range", func(t *testing.T) {
		t.Parallel()

		startTime := time.Now().Add(-1 * time.Hour)
		endTime := time.Now()

		mock := &mockCloudWatchLogsClient{
			getLogEventsFunc: func(_ context.Context, params *cloudwatchlogs.GetLogEventsInput, _ ...func(*cloudwatchlogs.Options)) (result *cloudwatchlogs.GetLogEventsOutput, err error) {
				assert.NotNil(t, params.StartTime)
				assert.NotNil(t, params.EndTime)
				assert.Equal(t, startTime.UnixMilli(), aws.ToInt64(params.StartTime))
				assert.Equal(t, endTime.UnixMilli(), aws.ToInt64(params.EndTime))

				result = &cloudwatchlogs.GetLogEventsOutput{
					Events: []types.OutputLogEvent{},
				}
				return result, err
			},
		}

		_, err := getLogEvents(ctx, mock, "/group", "stream", &startTime, &endTime, 100)

		require.NoError(t, err)
	})

	t.Run("error", func(t *testing.T) {
		t.Parallel()

		mock := &mockCloudWatchLogsClient{
			getLogEventsFunc: func(_ context.Context, _ *cloudwatchlogs.GetLogEventsInput, _ ...func(*cloudwatchlogs.Options)) (result *cloudwatchlogs.GetLogEventsOutput, err error) {
				err = errors.New("AWS error: log stream not found")
				return result, err
			},
		}

		_, err := getLogEvents(ctx, mock, "/group", "nonexistent", nil, nil, 100)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "getting log events")
	})
}

// TestParseQueryResults tests the query results parsing.
func TestParseQueryResults(t *testing.T) {
	t.Parallel()

	t.Run("with_results_and_stats", func(t *testing.T) {
		t.Parallel()

		output := &cloudwatchlogs.GetQueryResultsOutput{
			Status: types.QueryStatusComplete,
			Results: [][]types.ResultField{
				{
					{Field: aws.String("@timestamp"), Value: aws.String("2024-01-15 12:00:00")},
					{Field: aws.String("@message"), Value: aws.String("Log message 1")},
					{Field: aws.String("level"), Value: aws.String("ERROR")},
				},
				{
					{Field: aws.String("@timestamp"), Value: aws.String("2024-01-15 12:01:00")},
					{Field: aws.String("@message"), Value: aws.String("Log message 2")},
					{Field: aws.String("level"), Value: aws.String("INFO")},
				},
			},
			Statistics: &types.QueryStatistics{
				BytesScanned:   2048.0,
				RecordsMatched: 2.0,
				RecordsScanned: 500.0,
			},
		}

		initial := CloudWatchQueryResult{
			QueryID: "test-query",
			Region:  "us-east-1",
		}

		result := parseQueryResults(output, initial)

		assert.Equal(t, 2, result.ResultCount)
		assert.Len(t, result.Results, 2)
		assert.Equal(t, "Log message 1", result.Results[0]["@message"])
		assert.Equal(t, "ERROR", result.Results[0]["level"])
		assert.NotNil(t, result.Statistics)
		assert.InDelta(t, 2048.0, result.Statistics.BytesScanned, 0.001)
		assert.InDelta(t, 2.0, result.Statistics.RecordsMatched, 0.001)
		assert.InDelta(t, 500.0, result.Statistics.RecordsScanned, 0.001)
	})

	t.Run("without_statistics", func(t *testing.T) {
		t.Parallel()

		output := &cloudwatchlogs.GetQueryResultsOutput{
			Status: types.QueryStatusComplete,
			Results: [][]types.ResultField{
				{
					{Field: aws.String("@message"), Value: aws.String("Test")},
				},
			},
		}

		initial := CloudWatchQueryResult{QueryID: "test"}
		result := parseQueryResults(output, initial)

		assert.Nil(t, result.Statistics)
		assert.Equal(t, 1, result.ResultCount)
	})

	t.Run("empty_results", func(t *testing.T) {
		t.Parallel()

		output := &cloudwatchlogs.GetQueryResultsOutput{
			Status:  types.QueryStatusComplete,
			Results: [][]types.ResultField{},
		}

		initial := CloudWatchQueryResult{QueryID: "test"}
		result := parseQueryResults(output, initial)

		assert.Equal(t, 0, result.ResultCount)
		assert.Empty(t, result.Results)
	})

	t.Run("nil_field_values", func(t *testing.T) {
		t.Parallel()

		output := &cloudwatchlogs.GetQueryResultsOutput{
			Status: types.QueryStatusComplete,
			Results: [][]types.ResultField{
				{
					{Field: nil, Value: aws.String("value")},
					{Field: aws.String("key"), Value: nil},
					{Field: aws.String("valid"), Value: aws.String("value")},
				},
			},
		}

		initial := CloudWatchQueryResult{QueryID: "test"}
		result := parseQueryResults(output, initial)

		assert.Equal(t, 1, result.ResultCount)
		// Only the valid field should be present
		assert.Equal(t, "value", result.Results[0]["valid"])
		_, hasNilKey := result.Results[0][""]
		assert.False(t, hasNilKey)
	})
}

// TestGetCloudWatchTools tests the tool definitions.
func TestGetCloudWatchTools(t *testing.T) {
	t.Parallel()

	tools := getCloudWatchTools()

	assert.Len(t, tools, 3)

	// Verify tool names
	toolNames := make(map[string]bool)
	for _, tool := range tools {
		toolNames[tool.Name] = true
	}

	assert.True(t, toolNames[toolCloudWatchLogsQuery])
	assert.True(t, toolNames[toolCloudWatchLogsListGroups])
	assert.True(t, toolNames[toolCloudWatchLogsGetEvents])

	// Verify each tool has required fields
	for _, tool := range tools {
		assert.NotEmpty(t, tool.Name)
		assert.NotEmpty(t, tool.Description)
		assert.NotNil(t, tool.InputSchema)
	}
}

// TestServerExecuteCloudWatchLogsQuery tests the server's CloudWatch query execution.
func TestServerExecuteCloudWatchLogsQuery(t *testing.T) {
	// Cannot use t.Parallel() due to logger initialization

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx := context.Background()

	server := &Server{
		logger: logger,
	}

	t.Run("missing_query", func(t *testing.T) {
		args := map[string]interface{}{
			"log_groups": []interface{}{"/test/group"},
			"start_time": "1h",
		}

		_, err := server.executeCloudWatchLogsQuery(ctx, args)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "query parameter is required")
	})

	t.Run("missing_log_groups", func(t *testing.T) {
		args := map[string]interface{}{
			"query":      "fields @message",
			"start_time": "1h",
		}

		_, err := server.executeCloudWatchLogsQuery(ctx, args)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "log_groups parameter is required")
	})

	t.Run("missing_start_time", func(t *testing.T) {
		args := map[string]interface{}{
			"query":      "fields @message",
			"log_groups": []interface{}{"/test/group"},
		}

		_, err := server.executeCloudWatchLogsQuery(ctx, args)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "start_time parameter is required")
	})

	t.Run("invalid_start_time", func(t *testing.T) {
		args := map[string]interface{}{
			"query":      "fields @message",
			"log_groups": []interface{}{"/test/group"},
			"start_time": "invalid",
		}

		_, err := server.executeCloudWatchLogsQuery(ctx, args)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "parsing start_time")
	})
}

// TestListLogGroupsWithMock tests the listLogGroups function with mock client.
func TestListLogGroupsWithMock(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	t.Run("successful_list", func(t *testing.T) {
		t.Parallel()

		mockClient := &mockCloudWatchLogsClient{
			describeLogGroupsFunc: func(_ context.Context, _ *cloudwatchlogs.DescribeLogGroupsInput, _ ...func(*cloudwatchlogs.Options)) (result *cloudwatchlogs.DescribeLogGroupsOutput, err error) {
				result = &cloudwatchlogs.DescribeLogGroupsOutput{
					LogGroups: []types.LogGroup{
						{
							LogGroupName:      aws.String("/aws/lambda/test-function"),
							StoredBytes:       aws.Int64(1024),
							RetentionInDays:   aws.Int32(30),
							CreationTime:      aws.Int64(time.Now().UnixMilli()),
							Arn:               aws.String("arn:aws:logs:us-east-1:123456789:log-group:/aws/lambda/test-function"),
							MetricFilterCount: aws.Int32(2),
						},
						{
							LogGroupName:    aws.String("/ecs/test-service"),
							StoredBytes:     aws.Int64(2048),
							RetentionInDays: aws.Int32(14),
							CreationTime:    aws.Int64(time.Now().UnixMilli()),
							Arn:             aws.String("arn:aws:logs:us-east-1:123456789:log-group:/ecs/test-service"),
						},
					},
				}
				return result, err
			},
		}

		result, err := listLogGroups(ctx, mockClient, "", 50)

		require.NoError(t, err)
		require.Len(t, result, 2)
		assert.Equal(t, "/aws/lambda/test-function", result[0].Name)
		assert.Equal(t, "/ecs/test-service", result[1].Name)
		assert.Equal(t, int64(1024), result[0].StoredBytes)
		assert.Equal(t, int32(30), result[0].RetentionDays)
	})

	t.Run("with_prefix_filter", func(t *testing.T) {
		t.Parallel()

		mockClient := &mockCloudWatchLogsClient{
			describeLogGroupsFunc: func(_ context.Context, params *cloudwatchlogs.DescribeLogGroupsInput, _ ...func(*cloudwatchlogs.Options)) (result *cloudwatchlogs.DescribeLogGroupsOutput, err error) {
				// Verify prefix is passed to API
				assert.Equal(t, "/aws/lambda", *params.LogGroupNamePrefix)

				result = &cloudwatchlogs.DescribeLogGroupsOutput{
					LogGroups: []types.LogGroup{
						{
							LogGroupName: aws.String("/aws/lambda/test-function"),
							StoredBytes:  aws.Int64(512),
						},
					},
				}
				return result, err
			},
		}

		result, err := listLogGroups(ctx, mockClient, "/aws/lambda", 50)

		require.NoError(t, err)
		require.Len(t, result, 1)
		assert.Equal(t, "/aws/lambda/test-function", result[0].Name)
	})

	t.Run("api_error", func(t *testing.T) {
		t.Parallel()

		mockClient := &mockCloudWatchLogsClient{
			describeLogGroupsFunc: func(_ context.Context, _ *cloudwatchlogs.DescribeLogGroupsInput, _ ...func(*cloudwatchlogs.Options)) (result *cloudwatchlogs.DescribeLogGroupsOutput, err error) {
				err = errors.New("access denied")
				return result, err
			},
		}

		_, err := listLogGroups(ctx, mockClient, "", 50)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "access denied")
	})

	t.Run("empty_results", func(t *testing.T) {
		t.Parallel()

		mockClient := &mockCloudWatchLogsClient{
			describeLogGroupsFunc: func(_ context.Context, _ *cloudwatchlogs.DescribeLogGroupsInput, _ ...func(*cloudwatchlogs.Options)) (result *cloudwatchlogs.DescribeLogGroupsOutput, err error) {
				result = &cloudwatchlogs.DescribeLogGroupsOutput{
					LogGroups: []types.LogGroup{},
				}
				return result, err
			},
		}

		result, err := listLogGroups(ctx, mockClient, "", 50)

		require.NoError(t, err)
		assert.Empty(t, result)
	})
}

// TestServerExecuteCloudWatchLogsGetEvents tests the server's log event retrieval.
func TestServerExecuteCloudWatchLogsGetEvents(t *testing.T) {
	// Cannot use t.Parallel() due to logger initialization

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))
	ctx := context.Background()

	server := &Server{
		logger: logger,
	}

	t.Run("missing_log_group", func(t *testing.T) {
		args := map[string]interface{}{
			"log_stream": "test-stream",
		}

		_, err := server.executeCloudWatchLogsGetEvents(ctx, args)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "log_group parameter is required")
	})

	t.Run("missing_log_stream", func(t *testing.T) {
		args := map[string]interface{}{
			"log_group": "/test/group",
		}

		_, err := server.executeCloudWatchLogsGetEvents(ctx, args)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "log_stream parameter is required")
	})

	t.Run("invalid_start_time", func(t *testing.T) {
		args := map[string]interface{}{
			"log_group":  "/test/group",
			"log_stream": "stream",
			"start_time": "invalid",
		}

		_, err := server.executeCloudWatchLogsGetEvents(ctx, args)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "parsing start_time")
	})
}

// TestCloudWatchListLimitArg tests the list limit argument parsing.
func TestCloudWatchListLimitArg(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		args     map[string]interface{}
		expected int
	}{
		{
			name:     "default_list_limit",
			args:     map[string]interface{}{},
			expected: 50,
		},
		{
			name: "custom_list_limit",
			args: map[string]interface{}{
				"limit": float64(100),
			},
			expected: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result := parseCloudWatchListLimitArg(tt.args)
			assert.Equal(t, tt.expected, result)
		})
	}
}
