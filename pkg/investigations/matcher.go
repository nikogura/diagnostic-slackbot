package investigations

import (
	"fmt"
	"strings"
)

// MatchResult represents the outcome of matching a message to investigation skills.
type MatchResult struct {
	Matched           bool
	Skill             *InvestigationSkill
	InvestigationType InvestigationType
	Error             error
	MultipleMatches   []InvestigationType
}

// Matcher handles matching user messages to investigation skills.
type Matcher struct {
	library *SkillLibrary
}

// NewMatcher creates a new matcher with the given skill library.
func NewMatcher(library *SkillLibrary) (result *Matcher) {
	result = &Matcher{
		library: library,
	}

	return result
}

// Match attempts to match a user message to an investigation skill.
// Deprecated: Use MatchWithChannel for channel-aware matching.
func (m *Matcher) Match(message string) (result MatchResult) {
	result = m.MatchWithChannel(message, "")
	return result
}

// MatchWithChannel attempts to match a user message to an investigation skill,
// falling back to general-diagnostic when no specific pattern matches.
func (m *Matcher) MatchWithChannel(message, channelName string) (result MatchResult) {
	// First try pattern-based matching
	skill, invType, err := m.library.FindMatchingSkill(message)

	// If no match, fall back to general-diagnostic (catch-all)
	if err != nil {
		generalSkill, getErr := m.library.GetSkill(InvestigationTypeGeneralDiagnostic)
		if getErr == nil {
			result = MatchResult{
				Matched:           true,
				Skill:             generalSkill,
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
		Skill:             skill,
		InvestigationType: invType,
	}

	return result
}

// FormatAvailableInvestigations returns a formatted list of available investigation skills.
func (m *Matcher) FormatAvailableInvestigations() (result string) {
	types := m.library.ListSkills()

	if len(types) == 0 {
		result = "No investigation skills available."
		return result
	}

	var builder strings.Builder

	builder.WriteString("Available investigation skills:\n")

	for _, invType := range types {
		skill, err := m.library.GetSkill(invType)
		if err != nil {
			continue
		}

		fmt.Fprintf(&builder, "• *%s*: %s\n", skill.Name, skill.Description)
		fmt.Fprintf(&builder, "  Triggers: %s\n", strings.Join(skill.TriggerPatterns, ", "))
	}

	result = builder.String()
	return result
}
