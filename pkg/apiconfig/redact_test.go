package apiconfig

import (
	"encoding/json"
	"testing"
)

func TestRedactResponse_FlatObject(t *testing.T) {
	t.Parallel()

	input := `{"name":"John","email":"john@example.com","wallet_id":"abc123"}`
	fields := []string{"email"}

	result, err := redactResponse([]byte(input), fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]interface{}
	err = json.Unmarshal(result, &parsed)
	if err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}

	if parsed["email"] != "[redacted]" {
		t.Errorf("expected email to be [redacted], got %q", parsed["email"])
	}

	if parsed["name"] != "John" {
		t.Errorf("expected name to be preserved, got %q", parsed["name"])
	}

	if parsed["wallet_id"] != "abc123" {
		t.Errorf("expected wallet_id to be preserved, got %q", parsed["wallet_id"])
	}
}

func TestRedactResponse_NestedObject(t *testing.T) {
	t.Parallel()

	input := `{"user":{"email":"john@example.com","phone":"555-1234"},"id":"abc"}`
	fields := []string{"email", "phone"}

	result, err := redactResponse([]byte(input), fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]interface{}
	err = json.Unmarshal(result, &parsed)
	if err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}

	user, ok := parsed["user"].(map[string]interface{})
	if !ok {
		t.Fatal("expected user to be an object")
	}

	if user["email"] != "[redacted]" {
		t.Errorf("expected nested email to be [redacted], got %q", user["email"])
	}

	if user["phone"] != "[redacted]" {
		t.Errorf("expected nested phone to be [redacted], got %q", user["phone"])
	}
}

func TestRedactResponse_Array(t *testing.T) {
	t.Parallel()

	input := `[{"email":"a@b.com","id":"1"},{"email":"c@d.com","id":"2"}]`
	fields := []string{"email"}

	result, err := redactResponse([]byte(input), fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed []interface{}
	err = json.Unmarshal(result, &parsed)
	if err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}

	if len(parsed) != 2 {
		t.Fatalf("expected 2 items, got %d", len(parsed))
	}

	for i, item := range parsed {
		obj, ok := item.(map[string]interface{})
		if !ok {
			t.Fatalf("item %d is not an object", i)
		}
		if obj["email"] != "[redacted]" {
			t.Errorf("item %d: expected email [redacted], got %q", i, obj["email"])
		}
	}
}

func TestRedactResponse_CaseInsensitive(t *testing.T) {
	t.Parallel()

	input := `{"Email":"test@test.com","EMAIL":"other@test.com","id":"1"}`
	fields := []string{"email"}

	result, err := redactResponse([]byte(input), fields)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var parsed map[string]interface{}
	err = json.Unmarshal(result, &parsed)
	if err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}

	if parsed["Email"] != "[redacted]" {
		t.Errorf("expected Email to be [redacted], got %q", parsed["Email"])
	}

	if parsed["EMAIL"] != "[redacted]" {
		t.Errorf("expected EMAIL to be [redacted], got %q", parsed["EMAIL"])
	}
}

func TestRedactResponse_NoFields(t *testing.T) {
	t.Parallel()

	input := `{"email":"test@test.com"}`

	result, err := redactResponse([]byte(input), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(result) != input {
		t.Errorf("expected unchanged output when no fields specified")
	}
}

func TestRedactResponse_InvalidJSON(t *testing.T) {
	t.Parallel()

	input := `not json at all`
	fields := []string{"email"}

	result, err := redactResponse([]byte(input), fields)
	if err != nil {
		t.Fatalf("expected no error for invalid JSON, got: %v", err)
	}

	if string(result) != input {
		t.Errorf("expected unchanged output for invalid JSON")
	}
}
