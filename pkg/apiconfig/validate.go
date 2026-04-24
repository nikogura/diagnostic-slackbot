package apiconfig

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// pathTraversalPattern detects path traversal attempts.
var pathTraversalPattern = regexp.MustCompile(`\.\.[\\/]|[\\/]\.\.`)

// queryInjectionPattern detects query string injection in path params.
var queryInjectionPattern = regexp.MustCompile(`[?&#]`)

// validatePathParam validates a single path parameter value against its config.
func validatePathParam(param Param, value string) (err error) {
	if value == "" {
		if param.Required {
			err = fmt.Errorf("required parameter %q is empty", param.Name)
			return err
		}
		return err
	}

	// Always block path traversal
	if pathTraversalPattern.MatchString(value) {
		err = fmt.Errorf("parameter %q contains path traversal", param.Name)
		return err
	}

	// Always block query injection in path params
	if param.In == "path" && queryInjectionPattern.MatchString(value) {
		err = fmt.Errorf("parameter %q contains query injection characters", param.Name)
		return err
	}

	// Validate against custom regex if provided
	if param.Validate != "" {
		matched, matchErr := regexp.MatchString("^(?:"+param.Validate+")$", value)
		if matchErr != nil {
			err = fmt.Errorf("invalid validation pattern for %q: %w", param.Name, matchErr)
			return err
		}

		if !matched {
			err = fmt.Errorf("parameter %q value %q does not match pattern %q", param.Name, value, param.Validate)
			return err
		}
	}

	return err
}

// validateAndBuildURL validates all parameters and builds the final request URL.
func validateAndBuildURL(baseURL string, endpoint Endpoint, args map[string]interface{}) (requestURL string, queryParams map[string]string, err error) {
	path := endpoint.Path
	queryParams = make(map[string]string)

	for _, param := range endpoint.Params {
		value := extractStringArg(args, param.Name)

		err = validatePathParam(param, value)
		if err != nil {
			return requestURL, queryParams, err
		}

		if value == "" {
			continue
		}

		if param.In == "path" {
			placeholder := "{" + param.Name + "}"
			if !strings.Contains(path, placeholder) {
				err = fmt.Errorf("path parameter %q placeholder not found in path %q", param.Name, endpoint.Path)
				return requestURL, queryParams, err
			}
			path = strings.ReplaceAll(path, placeholder, value)
		} else {
			queryParams[param.Name] = value
		}
	}

	// Verify no unresolved path placeholders remain
	if strings.Contains(path, "{") {
		err = fmt.Errorf("unresolved path placeholders in %q", path)
		return requestURL, queryParams, err
	}

	requestURL = strings.TrimRight(baseURL, "/") + path

	return requestURL, queryParams, err
}

func extractStringArg(args map[string]interface{}, key string) (value string) {
	raw, ok := args[key]
	if !ok {
		return value
	}

	switch v := raw.(type) {
	case string:
		value = v
	case float64:
		value = fmt.Sprintf("%v", v)
	case bool:
		value = strconv.FormatBool(v)
	}

	return value
}
