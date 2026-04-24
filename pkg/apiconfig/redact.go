package apiconfig

import (
	"encoding/json"
	"strings"
)

const redactedValue = "[redacted]"

// redactResponse walks a JSON response and replaces values of sensitive fields with [redacted].
func redactResponse(body []byte, fields []string) (result []byte, err error) {
	if len(fields) == 0 {
		result = body
		return result, err
	}

	// Build lowercase lookup set
	fieldSet := make(map[string]bool, len(fields))
	for _, f := range fields {
		fieldSet[strings.ToLower(f)] = true
	}

	var parsed interface{}

	unmarshalErr := json.Unmarshal(body, &parsed)
	if unmarshalErr == nil {
		redacted := redactValue(parsed, fieldSet)
		result, err = json.Marshal(redacted)

		return result, err
	}

	// If we can't parse the JSON, return it unmodified
	result = body

	return result, err
}

func redactValue(v interface{}, fields map[string]bool) (result interface{}) {
	switch val := v.(type) {
	case map[string]interface{}:
		result = redactMap(val, fields)
	case []interface{}:
		result = redactSlice(val, fields)
	default:
		result = v
	}

	return result
}

func redactMap(m map[string]interface{}, fields map[string]bool) (result map[string]interface{}) {
	result = make(map[string]interface{}, len(m))

	for k, v := range m {
		if fields[strings.ToLower(k)] {
			result[k] = redactedValue
		} else {
			result[k] = redactValue(v, fields)
		}
	}

	return result
}

func redactSlice(s []interface{}, fields map[string]bool) (result []interface{}) {
	result = make([]interface{}, len(s))

	for i, v := range s {
		result[i] = redactValue(v, fields)
	}

	return result
}
