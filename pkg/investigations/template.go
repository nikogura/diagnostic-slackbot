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

// InvestigationTemplate defines the structure of an investigation workflow.
type InvestigationTemplate struct {
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

// LoadTemplate loads an investigation template from a YAML file.
func LoadTemplate(filePath string) (result *InvestigationTemplate, err error) {
	var data []byte

	data, err = os.ReadFile(filePath)
	if err != nil {
		err = fmt.Errorf("reading template file: %w", err)
		return result, err
	}

	var template InvestigationTemplate

	err = yaml.Unmarshal(data, &template)
	if err != nil {
		err = fmt.Errorf("parsing template YAML: %w", err)
		return result, err
	}

	// Compile trigger patterns into regexes
	template.triggerRegexes = make([]*regexp.Regexp, 0, len(template.TriggerPatterns))

	for _, pattern := range template.TriggerPatterns {
		var regex *regexp.Regexp

		regex, err = regexp.Compile("(?i)" + pattern)
		if err != nil {
			err = fmt.Errorf("compiling trigger pattern %q: %w", pattern, err)
			return result, err
		}

		template.triggerRegexes = append(template.triggerRegexes, regex)
	}

	result = &template
	return result, err
}

// Matches checks if the given message matches any of the trigger patterns.
func (t *InvestigationTemplate) Matches(message string) (result bool) {
	normalizedMessage := strings.ToLower(strings.TrimSpace(message))

	for _, regex := range t.triggerRegexes {
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
func (t *InvestigationTemplate) MatchWithSpecificity(message string) (matched bool, specificity int, pattern string) {
	normalizedMessage := strings.ToLower(strings.TrimSpace(message))

	var bestSpecificity int
	var bestPattern string

	for i, regex := range t.triggerRegexes {
		if regex.MatchString(normalizedMessage) {
			matched = true
			// Calculate specificity: pattern length minus wildcards
			patternStr := t.TriggerPatterns[i]
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

// TemplateLibrary manages a collection of investigation templates.
type TemplateLibrary struct {
	templates map[InvestigationType]*InvestigationTemplate
}

// NewTemplateLibrary creates a new template library by loading all templates
// from the specified directory.
func NewTemplateLibrary(templatesDir string) (result *TemplateLibrary, err error) {
	var entries []os.DirEntry

	lib := &TemplateLibrary{
		templates: make(map[InvestigationType]*InvestigationTemplate),
	}

	entries, err = os.ReadDir(templatesDir)
	if err != nil {
		err = fmt.Errorf("reading templates directory: %w", err)
		return result, err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		filePath := filepath.Join(templatesDir, entry.Name())

		var template *InvestigationTemplate

		template, err = LoadTemplate(filePath)
		if err != nil {
			err = fmt.Errorf("loading template %s: %w", entry.Name(), err)
			return result, err
		}

		// Map filename to investigation type
		investigationType := inferTypeFromFilename(entry.Name())
		lib.templates[investigationType] = template
	}

	if len(lib.templates) == 0 {
		err = fmt.Errorf("no valid templates found in %s", templatesDir)
		return result, err
	}

	result = lib
	return result, err
}

// FindMatchingTemplate finds the most specific template that matches the given message.
// When multiple templates match, returns the one with highest specificity score.
func (l *TemplateLibrary) FindMatchingTemplate(message string) (result *InvestigationTemplate, investigationType InvestigationType, err error) {
	type matchInfo struct {
		template    *InvestigationTemplate
		invType     InvestigationType
		specificity int
		pattern     string
	}

	var matches []matchInfo

	for invType, template := range l.templates {
		matched, specificity, pattern := template.MatchWithSpecificity(message)
		if matched {
			matches = append(matches, matchInfo{
				template:    template,
				invType:     invType,
				specificity: specificity,
				pattern:     pattern,
			})
		}
	}

	if len(matches) == 0 {
		err = errors.New("no matching investigation template found")
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

	result = bestMatch.template
	investigationType = bestMatch.invType

	return result, investigationType, err
}

// GetTemplate retrieves a template by its type.
func (l *TemplateLibrary) GetTemplate(invType InvestigationType) (result *InvestigationTemplate, err error) {
	template, exists := l.templates[invType]
	if !exists {
		err = fmt.Errorf("template not found for type: %s", invType)
		return result, err
	}

	result = template
	return result, err
}

// ListTemplates returns all available templates.
func (l *TemplateLibrary) ListTemplates() (result []InvestigationType) {
	result = make([]InvestigationType, 0, len(l.templates))

	for invType := range l.templates {
		result = append(result, invType)
	}

	return result
}

// inferTypeFromFilename maps template filenames to investigation types.
func inferTypeFromFilename(filename string) (result InvestigationType) {
	filename = strings.ToLower(filename)

	switch {
	case strings.Contains(filename, "modsec"):
		result = InvestigationTypeModSecurity
	case strings.Contains(filename, "atlas"):
		result = InvestigationTypeAtlas
	case strings.Contains(filename, "crashloop") || strings.Contains(filename, "pod"):
		result = InvestigationTypePodCrash
	case strings.Contains(filename, "general"):
		result = InvestigationTypeGeneralDiagnostic
	default:
		result = InvestigationTypeUnknown
	}

	return result
}
