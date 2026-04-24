package apiconfig

import (
	"testing"
)

func TestValidatePathParam_PathTraversal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
	}{
		{"dot-dot-slash", "../etc/passwd"},
		{"backslash-traversal", "..\\windows"},
		{"encoded-traversal", "foo/../bar"},
	}

	param := Param{Name: "id", Required: true, In: "path"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validatePathParam(param, tt.value)
			if err == nil {
				t.Errorf("expected error for path traversal value %q", tt.value)
			}
		})
	}
}

func TestValidatePathParam_QueryInjection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
	}{
		{"question-mark", "abc?query=evil"},
		{"ampersand", "abc&param=evil"},
		{"hash", "abc#fragment"},
	}

	param := Param{Name: "id", Required: true, In: "path"}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validatePathParam(param, tt.value)
			if err == nil {
				t.Errorf("expected error for query injection value %q", tt.value)
			}
		})
	}
}

func TestValidatePathParam_RegexValidation(t *testing.T) {
	t.Parallel()

	param := Param{Name: "wallet_id", Required: true, In: "path", Validate: "[a-f0-9]{24,}"}

	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{"valid-hex-24", "abcdef0123456789abcdef01", false},
		{"uppercase-rejected", "ABCDEF0123456789ABCDEF01", true},
		{"too-short", "abcdef01", true},
		{"special-chars", "abcdef01!@#$%^&*()", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validatePathParam(param, tt.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("validatePathParam(%q) error = %v, wantErr = %v", tt.value, err, tt.wantErr)
			}
		})
	}
}

func TestValidatePathParam_EmptyRequired(t *testing.T) {
	t.Parallel()

	param := Param{Name: "id", Required: true, In: "path"}
	err := validatePathParam(param, "")
	if err == nil {
		t.Error("expected error for empty required param")
	}
}

func TestValidatePathParam_EmptyOptional(t *testing.T) {
	t.Parallel()

	param := Param{Name: "filter", Required: false}
	err := validatePathParam(param, "")
	if err != nil {
		t.Errorf("unexpected error for empty optional param: %v", err)
	}
}

func TestValidateAndBuildURL(t *testing.T) {
	t.Parallel()

	endpoint := Endpoint{
		Name: "get_wallet",
		Path: "/api/v2/wallet/{wallet_id}",
		Params: []Param{
			{Name: "wallet_id", Type: "string", Required: true, In: "path", Validate: "[a-f0-9]{24,}"},
			{Name: "coin", Type: "string", Required: false, In: "query"},
		},
	}

	args := map[string]interface{}{
		"wallet_id": "abcdef0123456789abcdef01",
		"coin":      "btc",
	}

	requestURL, queryParams, err := validateAndBuildURL("https://api.bitgo.com", endpoint, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expectedURL := "https://api.bitgo.com/api/v2/wallet/abcdef0123456789abcdef01"
	if requestURL != expectedURL {
		t.Errorf("expected URL %q, got %q", expectedURL, requestURL)
	}

	if queryParams["coin"] != "btc" {
		t.Errorf("expected query param coin=btc, got %q", queryParams["coin"])
	}
}

func TestValidateAndBuildURL_UnresolvedPlaceholder(t *testing.T) {
	t.Parallel()

	endpoint := Endpoint{
		Name: "get_item",
		Path: "/api/v1/{item_id}",
		Params: []Param{
			{Name: "item_id", Type: "string", Required: false, In: "path"},
		},
	}

	args := map[string]interface{}{}

	_, _, err := validateAndBuildURL("https://api.example.com", endpoint, args)
	if err == nil {
		t.Error("expected error for unresolved placeholder")
	}
}
