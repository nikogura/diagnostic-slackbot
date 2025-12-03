package investigations

import (
	"fmt"
	"strings"
)

// MatchResult represents the outcome of matching a message to templates.
type MatchResult struct {
	Matched           bool
	Template          *InvestigationTemplate
	InvestigationType InvestigationType
	Error             error
	MultipleMatches   []InvestigationType
}

// Matcher handles matching user messages to investigation templates.
type Matcher struct {
	library *TemplateLibrary
}

// NewMatcher creates a new matcher with the given template library.
func NewMatcher(library *TemplateLibrary) (result *Matcher) {
	result = &Matcher{
		library: library,
	}

	return result
}

// Match attempts to match a user message to an investigation template.
// Deprecated: Use MatchWithChannel for channel-aware matching.
func (m *Matcher) Match(message string) (result MatchResult) {
	result = m.MatchWithChannel(message, "")
	return result
}

// MatchWithChannel attempts to match a user message to an investigation template,
// falling back to general-diagnostic when no specific pattern matches.
func (m *Matcher) MatchWithChannel(message, channelName string) (result MatchResult) {
	// First try pattern-based matching
	template, invType, err := m.library.FindMatchingTemplate(message)

	// If no match, fall back to general-diagnostic (catch-all)
	if err != nil {
		generalTemplate, getErr := m.library.GetTemplate(InvestigationTypeGeneralDiagnostic)
		if getErr == nil {
			result = MatchResult{
				Matched:           true,
				Template:          generalTemplate,
				InvestigationType: InvestigationTypeGeneralDiagnostic,
			}
			return result
		}

		// If even general-diagnostic is unavailable, return error
		result = MatchResult{
			Matched:           false,
			Error:             err,
			InvestigationType: InvestigationTypeUnknown,
		}
		return result
	}

	result = MatchResult{
		Matched:           true,
		Template:          template,
		InvestigationType: invType,
	}

	return result
}

// FormatAvailableInvestigations returns a formatted list of available investigation types.
func (m *Matcher) FormatAvailableInvestigations() (result string) {
	types := m.library.ListTemplates()

	if len(types) == 0 {
		result = "No investigation templates available."
		return result
	}

	var builder strings.Builder

	builder.WriteString("Available investigation types:\n")

	for _, invType := range types {
		template, err := m.library.GetTemplate(invType)
		if err != nil {
			continue
		}

		builder.WriteString(fmt.Sprintf("• *%s*: %s\n", template.Name, template.Description))
		builder.WriteString(fmt.Sprintf("  Triggers: %s\n", strings.Join(template.TriggerPatterns, ", ")))
	}

	result = builder.String()
	return result
}
