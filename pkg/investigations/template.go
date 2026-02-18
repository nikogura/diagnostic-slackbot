package investigations

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// InvestigationType represents the type of investigation being conducted.
type InvestigationType string

const (
	InvestigationTypeModSecurity       InvestigationType = "modsecurity"
	InvestigationTypeAtlas             InvestigationType = "atlas-migration"
	InvestigationTypePodCrash          InvestigationType = "pod-crashloop"
	InvestigationTypeGeneralDiagnostic InvestigationType = "general-diagnostic"
	InvestigationTypeCloudWatch        InvestigationType = "cloudwatch"
	InvestigationTypeDashboard         InvestigationType = "dashboard"
	InvestigationTypeDatabase          InvestigationType = "database"
	InvestigationTypeUnknown           InvestigationType = "unknown"
)

// K8sResourceType defines the type of Kubernetes resource to fetch.
type K8sResourceType string

const (
	K8sResourceTypeLogs       K8sResourceType = "logs"
	K8sResourceTypeConfigMap  K8sResourceType = "configmap"
	K8sResourceTypeDeployment K8sResourceType = "deployment"
	K8sResourceTypeService    K8sResourceType = "service"
	K8sResourceTypePod        K8sResourceType = "pod"
	K8sResourceTypeEvents     K8sResourceType = "events"
)

// K8sResource defines a Kubernetes resource to fetch for an investigation.
type K8sResource struct {
	Type      K8sResourceType `yaml:"type"`
	Namespace string          `yaml:"namespace,omitempty"`
	Name      string          `yaml:"name,omitempty"`
	Selector  string          `yaml:"selector,omitempty"`
	Container string          `yaml:"container,omitempty"`
	Since     string          `yaml:"since,omitempty"`
	Grep      string          `yaml:"grep,omitempty"`
	TailLines int             `yaml:"tail_lines,omitempty"`
}

// SinceDuration parses the Since field into a time.Duration.
func (r *K8sResource) SinceDuration() (result time.Duration, err error) {
	if r.Since == "" {
		result = 1 * time.Hour
		return result, err
	}

	result, err = time.ParseDuration(r.Since)
	return result, err
}

// InvestigationSkill defines the structure of an investigation skill.
// Each skill encapsulates domain-specific diagnostic expertise with trigger patterns,
// specialized prompts, and tool access for autonomous investigation workflows.
type InvestigationSkill struct {
	Name                string        `yaml:"name"`
	Description         string        `yaml:"description"`
	TriggerPatterns     []string      `yaml:"trigger_patterns"`
	InitialPrompt       string        `yaml:"initial_prompt"`
	KubernetesResources []K8sResource `yaml:"kubernetes_resources,omitempty"`
	ContextDocuments    []string      `yaml:"context_documents,omitempty"`
	RequireApproval     bool          `yaml:"require_approval"`

	// Computed fields
	triggerRegexes []*regexp.Regexp
}

// LoadSkill loads an investigation skill from a YAML file.
func LoadSkill(filePath string) (result *InvestigationSkill, err error) {
	var data []byte

	data, err = os.ReadFile(filePath)
	if err != nil {
		err = fmt.Errorf("reading skill file: %w", err)
		return result, err
	}

	var skill InvestigationSkill

	err = yaml.Unmarshal(data, &skill)
	if err != nil {
		err = fmt.Errorf("parsing skill YAML: %w", err)
		return result, err
	}

	// Compile trigger patterns into regexes
	skill.triggerRegexes = make([]*regexp.Regexp, 0, len(skill.TriggerPatterns))

	for _, pattern := range skill.TriggerPatterns {
		var regex *regexp.Regexp

		regex, err = regexp.Compile("(?i)" + pattern)
		if err != nil {
			err = fmt.Errorf("compiling trigger pattern %q: %w", pattern, err)
			return result, err
		}

		skill.triggerRegexes = append(skill.triggerRegexes, regex)
	}

	result = &skill
	return result, err
}

// Matches checks if the given message matches any of the trigger patterns.
func (s *InvestigationSkill) Matches(message string) (result bool) {
	normalizedMessage := strings.ToLower(strings.TrimSpace(message))

	for _, regex := range s.triggerRegexes {
		if regex.MatchString(normalizedMessage) {
			result = true
			return result
		}
	}

	return result
}

// MatchWithSpecificity checks if the message matches and returns specificity score.
// Higher scores indicate more specific matches.
// Returns (matched, specificity, matchedPattern).
func (s *InvestigationSkill) MatchWithSpecificity(message string) (matched bool, specificity int, pattern string) {
	normalizedMessage := strings.ToLower(strings.TrimSpace(message))

	var bestSpecificity int
	var bestPattern string

	for i, regex := range s.triggerRegexes {
		if regex.MatchString(normalizedMessage) {
			matched = true
			// Calculate specificity: pattern length minus wildcards
			patternStr := s.TriggerPatterns[i]
			// Remove common regex metacharacters to get "solid" pattern length
			solidPattern := strings.ReplaceAll(patternStr, ".*", "")
			solidPattern = strings.ReplaceAll(solidPattern, ".", "")
			solidPattern = strings.ReplaceAll(solidPattern, "*", "")
			solidPattern = strings.ReplaceAll(solidPattern, "+", "")
			solidPattern = strings.ReplaceAll(solidPattern, "?", "")

			patternSpecificity := len(solidPattern)

			if patternSpecificity > bestSpecificity {
				bestSpecificity = patternSpecificity
				bestPattern = patternStr
			}
		}
	}

	specificity = bestSpecificity
	pattern = bestPattern
	return matched, specificity, pattern
}

// SkillLibrary manages a collection of investigation skills.
// It provides skill selection based on message pattern matching with specificity ranking.
type SkillLibrary struct {
	skills map[InvestigationType]*InvestigationSkill
}

// NewSkillLibrary creates a new skill library by loading all investigation skills
// from the specified directory.
func NewSkillLibrary(skillsDir string) (result *SkillLibrary, err error) {
	var entries []os.DirEntry

	lib := &SkillLibrary{
		skills: make(map[InvestigationType]*InvestigationSkill),
	}

	entries, err = os.ReadDir(skillsDir)
	if err != nil {
		err = fmt.Errorf("reading skills directory: %w", err)
		return result, err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		filePath := filepath.Join(skillsDir, entry.Name())

		var skill *InvestigationSkill

		skill, err = LoadSkill(filePath)
		if err != nil {
			err = fmt.Errorf("loading skill %s: %w", entry.Name(), err)
			return result, err
		}

		// Map filename to investigation type
		investigationType := inferTypeFromFilename(entry.Name())
		lib.skills[investigationType] = skill
	}

	if len(lib.skills) == 0 {
		err = fmt.Errorf("no valid skills found in %s", skillsDir)
		return result, err
	}

	result = lib
	return result, err
}

// FindMatchingSkill finds the most specific skill that matches the given message.
// When multiple skills match, returns the one with highest specificity score.
func (l *SkillLibrary) FindMatchingSkill(message string) (result *InvestigationSkill, investigationType InvestigationType, err error) {
	type matchInfo struct {
		skill       *InvestigationSkill
		invType     InvestigationType
		specificity int
		pattern     string
	}

	var matches []matchInfo

	for invType, skill := range l.skills {
		matched, specificity, pattern := skill.MatchWithSpecificity(message)
		if matched {
			matches = append(matches, matchInfo{
				skill:       skill,
				invType:     invType,
				specificity: specificity,
				pattern:     pattern,
			})
		}
	}

	if len(matches) == 0 {
		err = errors.New("no matching investigation skill found")
		investigationType = InvestigationTypeUnknown

		return result, investigationType, err
	}

	// Find the most specific match (highest specificity score)
	bestMatch := matches[0]
	for _, match := range matches[1:] {
		if match.specificity > bestMatch.specificity {
			bestMatch = match
		}
	}

	result = bestMatch.skill
	investigationType = bestMatch.invType

	return result, investigationType, err
}

// GetSkill retrieves a skill by its type.
func (l *SkillLibrary) GetSkill(invType InvestigationType) (result *InvestigationSkill, err error) {
	skill, exists := l.skills[invType]
	if !exists {
		err = fmt.Errorf("skill not found for type: %s", invType)
		return result, err
	}

	result = skill
	return result, err
}

// ListSkills returns all available investigation skills.
func (l *SkillLibrary) ListSkills() (result []InvestigationType) {
	result = make([]InvestigationType, 0, len(l.skills))

	for invType := range l.skills {
		result = append(result, invType)
	}

	return result
}

// inferTypeFromFilename maps skill filenames to investigation types.
func inferTypeFromFilename(filename string) (result InvestigationType) {
	filename = strings.ToLower(filename)

	switch {
	case strings.Contains(filename, "modsec"):
		result = InvestigationTypeModSecurity
	case strings.Contains(filename, "atlas"):
		result = InvestigationTypeAtlas
	case strings.Contains(filename, "crashloop") || strings.Contains(filename, "pod"):
		result = InvestigationTypePodCrash
	case strings.Contains(filename, "cloudwatch"):
		result = InvestigationTypeCloudWatch
	case strings.Contains(filename, "dashboard"):
		result = InvestigationTypeDashboard
	case strings.Contains(filename, "database"):
		result = InvestigationTypeDatabase
	case strings.Contains(filename, "general"):
		result = InvestigationTypeGeneralDiagnostic
	default:
		result = InvestigationTypeUnknown
	}

	return result
}
