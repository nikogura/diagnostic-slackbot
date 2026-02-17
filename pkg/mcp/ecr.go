package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

// Severity level constants for vulnerability classification.
const (
	SeverityCritical      = "CRITICAL"
	SeverityHigh          = "HIGH"
	SeverityMedium        = "MEDIUM"
	SeverityLow           = "LOW"
	SeverityInformational = "INFORMATIONAL"
	SeverityUndefined     = "UNDEFINED"
)

// ECRScanResult represents the vulnerability scan results for an ECR image.
type ECRScanResult struct {
	AccountID       string                 `json:"account_id"`
	Region          string                 `json:"region"`
	RepositoryName  string                 `json:"repository_name"`
	ImageTag        string                 `json:"image_tag"`
	ImageDigest     string                 `json:"image_digest"`
	PushedAt        time.Time              `json:"pushed_at"`
	ScanStatus      string                 `json:"scan_status"`
	Vulnerabilities VulnerabilitySummary   `json:"vulnerabilities"`
	Findings        []VulnerabilityFinding `json:"findings,omitempty"`
}

// VulnerabilitySummary contains vulnerability counts by severity.
type VulnerabilitySummary struct {
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
	Informational int `json:"informational"`
	Undefined     int `json:"undefined"`
}

// VulnerabilityFinding represents a single CVE finding.
type VulnerabilityFinding struct {
	Name         string   `json:"name"`     // CVE ID
	Severity     string   `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
	CVSS         float64  `json:"cvss,omitempty"`
	Description  string   `json:"description,omitempty"`
	URI          string   `json:"uri,omitempty"`
	Packages     []string `json:"packages"` // Affected package names
	FixAvailable bool     `json:"fix_available"`
}

// executeECRScanResults queries AWS ECR for vulnerability scan results.
func (s *Server) executeECRScanResults(ctx context.Context, args map[string]interface{}) (result string, err error) {
	// Parse arguments
	var accounts []string
	var regions []string
	var repositories []string
	var maxAgeDays int
	var minSeverity string

	accounts, err = parseAccountsArg(args)
	if err != nil {
		return result, err
	}

	regions = parseRegionsArg(args)
	maxAgeDays = parseMaxAgeDaysArg(args)
	minSeverity = parseMinSeverityArg(args)
	repositories = parseRepositoriesArg(args)

	s.logger.InfoContext(ctx, "querying ECR for vulnerability scan results",
		"accounts", accounts,
		"regions", regions,
		"max_age_days", maxAgeDays,
		"min_severity", minSeverity,
		"repositories", repositories)

	// Query ECR across all accounts and regions
	var allResults []ECRScanResult

	for _, account := range accounts {
		for _, region := range regions {
			accountResults, queryErr := s.queryECRInAccount(ctx, account, region, maxAgeDays, minSeverity, repositories)
			if queryErr != nil {
				s.logger.WarnContext(ctx, "failed to query ECR in account/region",
					"account", account,
					"region", region,
					"error", queryErr.Error())
				// Continue with other accounts/regions
				continue
			}
			allResults = append(allResults, accountResults...)
		}
	}

	if len(allResults) == 0 {
		result = fmt.Sprintf("No ECR images found in accounts %v (regions: %v) within the last %d days",
			accounts, regions, maxAgeDays)
		return result, err
	}

	// Format results as structured text for Claude
	result = s.formatECRResults(allResults, accounts, regions, maxAgeDays, minSeverity)
	return result, err
}

// queryECRInAccount queries ECR repositories in a specific account and region.
func (s *Server) queryECRInAccount(
	ctx context.Context,
	accountID string,
	region string,
	maxAgeDays int,
	minSeverity string,
	repositories []string,
) (results []ECRScanResult, err error) {
	// Load AWS config
	cfg, loadErr := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if loadErr != nil {
		err = fmt.Errorf("loading AWS config: %w", loadErr)
		return results, err
	}

	s.logger.InfoContext(ctx, "loaded AWS config",
		"region", region,
		"account", accountID)

	// Create ECR client
	ecrClient := ecr.NewFromConfig(cfg)

	// List repositories
	var repoNames []string
	if len(repositories) > 0 {
		// Use specified repositories
		repoNames = repositories
	} else {
		// List all repositories
		var descReposErr error
		repoNames, descReposErr = s.listAllRepositories(ctx, ecrClient)
		if descReposErr != nil {
			err = fmt.Errorf("listing repositories: %w", descReposErr)
			return results, err
		}
	}

	s.logger.InfoContext(ctx, "found repositories to scan",
		"count", len(repoNames),
		"repositories", repoNames)

	cutoffTime := time.Now().AddDate(0, 0, -maxAgeDays)

	// For each repository, get images and scan results
	for _, repoName := range repoNames {
		repoResults, repoErr := s.scanRepository(ctx, ecrClient, accountID, region, repoName, cutoffTime)
		if repoErr != nil {
			s.logger.WarnContext(ctx, "failed to scan repository",
				"repository", repoName,
				"error", repoErr.Error())
			// Continue with other repositories
			continue
		}

		// Filter by minimum severity if specified
		for _, result := range repoResults {
			if shouldIncludeResult(result, minSeverity) {
				results = append(results, result)
			}
		}
	}

	return results, err
}

// listAllRepositories lists all ECR repositories in the account.
func (s *Server) listAllRepositories(ctx context.Context, ecrClient *ecr.Client) (repoNames []string, err error) {
	var nextToken *string

	for {
		output, listErr := ecrClient.DescribeRepositories(ctx, &ecr.DescribeRepositoriesInput{
			NextToken: nextToken,
		})
		if listErr != nil {
			err = fmt.Errorf("describing repositories: %w", listErr)
			return repoNames, err
		}

		for _, repo := range output.Repositories {
			if repo.RepositoryName != nil {
				repoNames = append(repoNames, *repo.RepositoryName)
			}
		}

		if output.NextToken == nil {
			break
		}
		nextToken = output.NextToken
	}

	return repoNames, err
}

// scanRepository scans a single repository for vulnerability findings.
func (s *Server) scanRepository(
	ctx context.Context,
	ecrClient *ecr.Client,
	accountID string,
	region string,
	repoName string,
	cutoffTime time.Time,
) (results []ECRScanResult, err error) {
	var nextToken *string

	for {
		// List images in repository
		imagesOutput, listErr := ecrClient.DescribeImages(ctx, &ecr.DescribeImagesInput{
			RepositoryName: aws.String(repoName),
			NextToken:      nextToken,
		})
		if listErr != nil {
			err = fmt.Errorf("describing images in %s: %w", repoName, listErr)
			return results, err
		}

		// Process each image
		for _, imageDetail := range imagesOutput.ImageDetails {
			// Skip images older than cutoff
			if imageDetail.ImagePushedAt == nil || imageDetail.ImagePushedAt.Before(cutoffTime) {
				continue
			}

			// Get primary tag (or use digest if untagged)
			imageTag := "untagged"
			if len(imageDetail.ImageTags) > 0 {
				imageTag = imageDetail.ImageTags[0]
			}

			imageDigest := ""
			if imageDetail.ImageDigest != nil {
				imageDigest = *imageDetail.ImageDigest
			}

			// Get scan findings
			scanResult := s.getScanFindings(ctx, ecrClient, accountID, region, repoName, imageTag,
				imageDigest, imageDetail.ImagePushedAt)

			results = append(results, scanResult)
		}

		if imagesOutput.NextToken == nil {
			break
		}
		nextToken = imagesOutput.NextToken
	}

	return results, err
}

// getScanFindings retrieves vulnerability scan findings for a specific image.
func (s *Server) getScanFindings(
	ctx context.Context,
	ecrClient *ecr.Client,
	accountID string,
	region string,
	repoName string,
	imageTag string,
	imageDigest string,
	pushedAt *time.Time,
) (result ECRScanResult) {
	result = ECRScanResult{
		AccountID:      accountID,
		Region:         region,
		RepositoryName: repoName,
		ImageTag:       imageTag,
		ImageDigest:    imageDigest,
		PushedAt:       *pushedAt,
		ScanStatus:     "UNKNOWN",
	}

	// Get scan findings
	scanOutput, scanErr := ecrClient.DescribeImageScanFindings(ctx, &ecr.DescribeImageScanFindingsInput{
		RepositoryName: aws.String(repoName),
		ImageId: &types.ImageIdentifier{
			ImageDigest: aws.String(imageDigest),
		},
	})
	if scanErr != nil {
		s.logger.WarnContext(ctx, "failed to get scan findings",
			"repository", repoName,
			"tag", imageTag,
			"error", scanErr.Error())
		result.ScanStatus = "FAILED"
		return result
	}

	// Parse scan status
	if scanOutput.ImageScanStatus != nil && scanOutput.ImageScanStatus.Status != "" {
		result.ScanStatus = string(scanOutput.ImageScanStatus.Status)
	}

	// Parse scan findings
	if scanOutput.ImageScanFindings != nil {
		// Parse severity counts
		result.Vulnerabilities = parseSeverityCounts(scanOutput.ImageScanFindings.FindingSeverityCounts)

		// Parse detailed findings (CRITICAL and HIGH only to avoid overwhelming output)
		for _, finding := range scanOutput.ImageScanFindings.Findings {
			if finding.Severity != types.FindingSeverityCritical &&
				finding.Severity != types.FindingSeverityHigh {
				continue
			}

			vulnFinding := VulnerabilityFinding{
				Severity: string(finding.Severity),
			}

			if finding.Name != nil {
				vulnFinding.Name = *finding.Name
			}

			if finding.Description != nil {
				vulnFinding.Description = *finding.Description
			}

			if finding.Uri != nil {
				vulnFinding.URI = *finding.Uri
			}

			// Extract CVSS score and package info from attributes
			vulnFinding.CVSS, vulnFinding.Packages = extractFindingAttributes(finding.Attributes, vulnFinding.CVSS)

			result.Findings = append(result.Findings, vulnFinding)
		}
	}

	return result
}

// shouldIncludeResult determines if a result should be included based on minimum severity.
func shouldIncludeResult(result ECRScanResult, minSeverity string) (include bool) {
	if minSeverity == "" {
		include = true
		return include
	}

	switch minSeverity {
	case SeverityCritical:
		include = result.Vulnerabilities.Critical > 0
	case SeverityHigh:
		include = result.Vulnerabilities.Critical > 0 || result.Vulnerabilities.High > 0
	case SeverityMedium:
		include = result.Vulnerabilities.Critical > 0 || result.Vulnerabilities.High > 0 ||
			result.Vulnerabilities.Medium > 0
	case SeverityLow:
		include = result.Vulnerabilities.Critical > 0 || result.Vulnerabilities.High > 0 ||
			result.Vulnerabilities.Medium > 0 || result.Vulnerabilities.Low > 0
	default:
		include = true
	}

	return include
}

// parseSeverityCounts converts AWS ECR severity counts to our internal structure.
func parseSeverityCounts(counts map[string]int32) (summary VulnerabilitySummary) {
	for severityStr, count := range counts {
		switch severityStr {
		case SeverityCritical:
			summary.Critical = int(count)
		case SeverityHigh:
			summary.High = int(count)
		case SeverityMedium:
			summary.Medium = int(count)
		case SeverityLow:
			summary.Low = int(count)
		case SeverityInformational:
			summary.Informational = int(count)
		case SeverityUndefined:
			summary.Undefined = int(count)
		}
	}

	return summary
}

// extractFindingAttributes extracts CVSS score and package names from finding attributes.
func extractFindingAttributes(attributes []types.Attribute, currentCVSS float64) (cvss float64, packages []string) {
	cvss = currentCVSS

	for _, attr := range attributes {
		if attr.Key == nil || attr.Value == nil {
			continue
		}

		switch *attr.Key {
		case "CVSS2_SCORE", "CVSS3_SCORE":
			score, parseErr := strconv.ParseFloat(*attr.Value, 64)
			if parseErr == nil && score > cvss {
				cvss = score
			}
		case "package_name":
			packages = append(packages, *attr.Value)
		}
	}

	return cvss, packages
}

// parseAccountsArg parses the accounts argument from the args map.
func parseAccountsArg(args map[string]interface{}) (accounts []string, err error) {
	accountsRaw, argOK := args["accounts"].([]interface{})
	if !argOK || len(accountsRaw) == 0 {
		err = errors.New("accounts parameter is required and must be a non-empty array")
		return accounts, err
	}

	for _, acc := range accountsRaw {
		accStr, strOK := acc.(string)
		if strOK {
			accounts = append(accounts, accStr)
		}
	}

	return accounts, err
}

// parseRegionsArg parses the regions argument from the args map.
func parseRegionsArg(args map[string]interface{}) (regions []string) {
	regions = []string{"us-east-1"}

	regionsRaw, argOK := args["regions"].([]interface{})
	if argOK && len(regionsRaw) > 0 {
		regions = nil
		for _, reg := range regionsRaw {
			regStr, strOK := reg.(string)
			if strOK {
				regions = append(regions, regStr)
			}
		}
	}

	return regions
}

// parseMaxAgeDaysArg parses the max_age_days argument from the args map.
func parseMaxAgeDaysArg(args map[string]interface{}) (maxAgeDays int) {
	maxAgeDays = 30

	maxAgeFloat, argOK := args["max_age_days"].(float64)
	if argOK {
		maxAgeDays = int(maxAgeFloat)
	}

	return maxAgeDays
}

// parseMinSeverityArg parses the min_severity argument from the args map.
func parseMinSeverityArg(args map[string]interface{}) (minSeverity string) {
	minSevStr, argOK := args["min_severity"].(string)
	if argOK {
		minSeverity = strings.ToUpper(minSevStr)
	}

	return minSeverity
}

// parseRepositoriesArg parses the repositories argument from the args map.
func parseRepositoriesArg(args map[string]interface{}) (repositories []string) {
	reposRaw, argOK := args["repositories"].([]interface{})
	if argOK {
		for _, repo := range reposRaw {
			repoStr, strOK := repo.(string)
			if strOK {
				repositories = append(repositories, repoStr)
			}
		}
	}

	return repositories
}

// formatDetailedFindings formats the detailed CRITICAL and HIGH findings.
func formatDetailedFindings(builder *strings.Builder, findings []VulnerabilityFinding) {
	if len(findings) == 0 {
		return
	}

	builder.WriteString("\n**Critical/High Findings:**\n")
	for _, finding := range findings {
		if finding.Severity != SeverityCritical && finding.Severity != SeverityHigh {
			continue
		}

		fmt.Fprintf(builder, "\n- **%s** (%s, CVSS: %.1f)\n",
			finding.Name, finding.Severity, finding.CVSS)

		if finding.Description != "" {
			fmt.Fprintf(builder, "  - Description: %s\n", finding.Description)
		}

		if len(finding.Packages) > 0 {
			fmt.Fprintf(builder, "  - Packages: %s\n", strings.Join(finding.Packages, ", "))
		}

		if finding.FixAvailable {
			builder.WriteString("  - Fix Available: Yes\n")
		} else {
			builder.WriteString("  - Fix Available: No\n")
		}
	}
}

// formatECRResults formats ECR scan results as human-readable text.
func (s *Server) formatECRResults(
	results []ECRScanResult,
	accounts []string,
	regions []string,
	maxAgeDays int,
	minSeverity string,
) (output string) {
	var builder strings.Builder

	// Summary statistics
	totalImages := len(results)
	var totalCritical, totalHigh, totalMedium, totalLow int

	for _, result := range results {
		totalCritical += result.Vulnerabilities.Critical
		totalHigh += result.Vulnerabilities.High
		totalMedium += result.Vulnerabilities.Medium
		totalLow += result.Vulnerabilities.Low
	}

	builder.WriteString("# ECR Vulnerability Scan Results\n\n")
	builder.WriteString("**Query Parameters:**\n")
	fmt.Fprintf(&builder, "- Accounts: %s\n", strings.Join(accounts, ", "))
	fmt.Fprintf(&builder, "- Regions: %s\n", strings.Join(regions, ", "))
	fmt.Fprintf(&builder, "- Image Age Filter: Last %d days\n", maxAgeDays)
	if minSeverity != "" {
		fmt.Fprintf(&builder, "- Minimum Severity: %s\n", minSeverity)
	}
	builder.WriteString("\n**Summary:**\n")
	fmt.Fprintf(&builder, "- Total Images Scanned: %d\n", totalImages)
	fmt.Fprintf(&builder, "- Total Vulnerabilities: %d\n", totalCritical+totalHigh+totalMedium+totalLow)
	fmt.Fprintf(&builder, "  - CRITICAL: %d\n", totalCritical)
	fmt.Fprintf(&builder, "  - HIGH: %d\n", totalHigh)
	fmt.Fprintf(&builder, "  - MEDIUM: %d\n", totalMedium)
	fmt.Fprintf(&builder, "  - LOW: %d\n", totalLow)
	builder.WriteString("\n")

	// Detailed results per image
	builder.WriteString("## Image Details\n\n")

	for _, result := range results {
		fmt.Fprintf(&builder, "### %s:%s\n", result.RepositoryName, result.ImageTag)
		fmt.Fprintf(&builder, "- **Account:** %s\n", result.AccountID)
		fmt.Fprintf(&builder, "- **Region:** %s\n", result.Region)
		fmt.Fprintf(&builder, "- **Pushed:** %s (%d days ago)\n",
			result.PushedAt.Format("2006-01-02 15:04:05"),
			int(time.Since(result.PushedAt).Hours()/24))
		fmt.Fprintf(&builder, "- **Scan Status:** %s\n", result.ScanStatus)
		fmt.Fprintf(&builder, "- **Digest:** %s\n", result.ImageDigest)
		builder.WriteString("- **Vulnerabilities:**\n")
		fmt.Fprintf(&builder, "  - CRITICAL: %d\n", result.Vulnerabilities.Critical)
		fmt.Fprintf(&builder, "  - HIGH: %d\n", result.Vulnerabilities.High)
		fmt.Fprintf(&builder, "  - MEDIUM: %d\n", result.Vulnerabilities.Medium)
		fmt.Fprintf(&builder, "  - LOW: %d\n", result.Vulnerabilities.Low)

		// Include detailed findings if available
		formatDetailedFindings(&builder, result.Findings)

		builder.WriteString("\n")
	}

	// Include JSON data for programmatic processing
	builder.WriteString("## Raw Data (JSON)\n\n")
	builder.WriteString("```json\n")

	jsonData, _ := json.MarshalIndent(results, "", "  ")
	builder.Write(jsonData)
	builder.WriteString("\n```\n")

	output = builder.String()
	return output
}
