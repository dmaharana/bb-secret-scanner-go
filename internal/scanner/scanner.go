package scanner

import (
	"bufio"
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"bitbucket-secrets-scanner/internal/bitbucket"
	"bitbucket-secrets-scanner/pkg/util"
)

// Secret represents a detected secret in a file
type Secret struct {
	ProjectKey     string  `json:"project_key"`
	RepositorySlug string  `json:"repository_slug"`
	CommitID       string  `json:"commit_id"`
	CommitDate     string  `json:"commit_date"`
	CommitAuthor   string  `json:"commit_author"`
	Filename       string  `json:"filename"`
	LineNumber     int     `json:"line_number"`
	SecretType     string  `json:"secret_type"`
	SecretValue    string  `json:"secret_value"`
	Confidence     float64 `json:"confidence"`
	EndLine        int     `json:"end_line,omitempty"` // For multi-line secrets
}

// SecretFileInfo contains metadata about a file being scanned
type SecretFileInfo struct {
	ProjectKey     string
	RepositorySlug string
	CommitID       string
	CommitDate     string
	CommitAuthor   string
	Filename       string
}

// FileScanner scans individual files for secrets
type FileScanner struct {
	detector *SecretDetector
}

// NewFileScanner creates a new file scanner
func NewFileScanner(detector *SecretDetector) *FileScanner {
	return &FileScanner{
		detector: detector,
	}
}

// getGitRepoInfo retrieves Git repository information for a given file path
func getGitRepoInfo(filePath string) (string, string, string, string, string) {
	// Default values if Git info is unavailable
	projectKey := "local"
	repoSlug := "local"
	commitID := "local"
	commitDate := time.Now().Format("2006-01-02 15:04:05")
	commitAuthor := "local"

	// Find the Git repository root
	dir := filepath.Dir(filePath)
	for dir != "/" && dir != "." {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			break
		}
		dir = filepath.Dir(dir)
	}

	// Extract repository slug from the directory name
	if dir != "/" && dir != "." {
		repoSlug = filepath.Base(dir)
	}

	// Extract project key from parent directory (one level up)
	if parentDir := filepath.Dir(dir); parentDir != "/" && parentDir != "." {
		projectKey = filepath.Base(parentDir)
	}

	// Run Git commands to get commit information
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir
	if output, err := cmd.Output(); err == nil {
		commitID = strings.TrimSpace(string(output))
	}

	// Get the latest commit date and author for the file
	cmd = exec.Command("git", "log", "-1", "--pretty=%ci|%an <%ae>", filePath)
	cmd.Dir = dir
	if output, err := cmd.Output(); err == nil {
		parts := strings.SplitN(strings.TrimSpace(string(output)), "|", 2)
		if len(parts) == 2 {
			// Parse commit date
			if t, err := time.Parse("2006-01-02 15:04:05 -0700", parts[0]); err == nil {
				commitDate = t.Format("2006-01-02 15:04:05")
			}
			commitAuthor = parts[1]
		}
	}

	return projectKey, repoSlug, commitID, commitDate, commitAuthor
}

// ScanFile scans a single file for secrets
func (s *FileScanner) ScanFile(filePath string) ([]Secret, error) {
	// skip if path has .git in it
	if strings.Contains(filePath, ".git") {
		return nil, nil
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Get Git repository information
	projectKey, repoSlug, commitID, commitDate, commitAuthor := getGitRepoInfo(filePath)

	fileInfo := SecretFileInfo{
		ProjectKey:     projectKey,
		RepositorySlug: repoSlug,
		CommitID:       commitID,
		CommitDate:     commitDate,
		CommitAuthor:   commitAuthor,
		Filename:       filePath,
	}

	return s.scanContent(file, fileInfo)
}

// scanContent scans the content of a reader for secrets
func (s *FileScanner) scanContent(file *os.File, fileInfo SecretFileInfo) ([]Secret, error) {
	// Read entire file content for multi-line scanning
	content, err := os.ReadFile(file.Name())
	if err != nil {
		return nil, err
	}

	// First, scan for multi-line secrets (prioritizing private keys)
	multilineSecrets, privateKeyRegions := s.scanMultilineSecrets(string(content), fileInfo)

	// Reset file pointer for line-by-line scanning
	if _, err := file.Seek(0, 0); err != nil {
		return nil, err
	}

	// Then scan line by line for single-line secrets, skipping private key regions
	scanner := bufio.NewScanner(file)
	lineNum := 0
	var singleLineSecrets []Secret

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip lines that are part of a private key region
		if isLineInPrivateKeyRegion(lineNum, privateKeyRegions) {
			continue
		}

		lineSecrets := s.detector.DetectSecrets(line, lineNum, fileInfo)
		for _, secret := range lineSecrets {
			if secret.Confidence < 50 {
				log.Printf("Skipped low-confidence secret at %s:%d: %s (Confidence: %.2f)", fileInfo.Filename, lineNum, secret.SecretValue, secret.Confidence)
				continue
			}
			singleLineSecrets = append(singleLineSecrets, secret)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Combine all secrets
	allSecrets := append(singleLineSecrets, multilineSecrets...)

	// Output as JSON
	jsonOutput, err := json.MarshalIndent(allSecrets, "", "  ")
	if err == nil {
		log.Printf("Secrets found in %s: %s", fileInfo.Filename, string(jsonOutput))
	}

	return allSecrets, nil
}

// scanMultilineSecrets scans for secrets that span multiple lines
func (s *FileScanner) scanMultilineSecrets(content string, fileInfo SecretFileInfo) ([]Secret, []Region) {
	var secrets []Secret
	var privateKeyRegions []Region

	// Detect SSH Private Keys
	sshPrivateKeys, regions := detectMultilineSecret(
		content,
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"-----END OPENSSH PRIVATE KEY-----",
		"SSH Private Key",
		fileInfo,
	)
	secrets = append(secrets, sshPrivateKeys...)
	privateKeyRegions = append(privateKeyRegions, regions...)

	// Detect RSA Private Keys
	rsaPrivateKeys, regions := detectMultilineSecret(
		content,
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----END RSA PRIVATE KEY-----",
		"RSA Private Key",
		fileInfo,
	)
	secrets = append(secrets, rsaPrivateKeys...)
	privateKeyRegions = append(privateKeyRegions, regions...)

	// Detect PGP Private Keys
	pgpPrivateKeys, regions := detectMultilineSecret(
		content,
		"-----BEGIN PGP PRIVATE KEY BLOCK-----",
		"-----END PGP PRIVATE KEY BLOCK-----",
		"PGP Private Key",
		fileInfo,
	)
	secrets = append(secrets, pgpPrivateKeys...)
	privateKeyRegions = append(privateKeyRegions, regions...)

	// Detect EC Private Keys
	ecPrivateKeys, regions := detectMultilineSecret(
		content,
		"-----BEGIN EC PRIVATE KEY-----",
		"-----END EC PRIVATE KEY-----",
		"EC Private Key",
		fileInfo,
	)
	secrets = append(secrets, ecPrivateKeys...)
	privateKeyRegions = append(privateKeyRegions, regions...)

	// Detect PRIVATE KEYs (generic)
	genericPrivateKeys, regions := detectMultilineSecret(
		content,
		"-----BEGIN PRIVATE KEY-----",
		"-----END PRIVATE KEY-----",
		"Private Key",
		fileInfo,
	)
	secrets = append(secrets, genericPrivateKeys...)
	privateKeyRegions = append(privateKeyRegions, regions...)

	return secrets, privateKeyRegions
}

// Region represents a range of lines covered by a private key
type Region struct {
	StartLine int
	EndLine   int
}

// isLineInPrivateKeyRegion checks if a line number falls within any private key region
func isLineInPrivateKeyRegion(lineNum int, regions []Region) bool {
	for _, region := range regions {
		if lineNum >= region.StartLine && lineNum <= region.EndLine {
			return true
		}
	}
	return false
}

// detectMultilineSecret detects secrets that span multiple lines with a specific start and end marker
func detectMultilineSecret(content, startMarker, endMarker, secretType string, fileInfo SecretFileInfo) ([]Secret, []Region) {
	var secrets []Secret
	var regions []Region

	// Find all occurrences of the start marker
	startMarkerRegex := regexp.MustCompile(regexp.QuoteMeta(startMarker))
	startMatches := startMarkerRegex.FindAllStringIndex(content, -1)

	for _, startMatch := range startMatches {
		// Look for the end marker after this start position
		endMarkerRegex := regexp.MustCompile(regexp.QuoteMeta(endMarker))
		endMatches := endMarkerRegex.FindStringIndex(content[startMatch[1]:])

		if len(endMatches) > 0 {
			// We found a complete key
			secretStart := startMatch[0]
			secretEnd := startMatch[1] + endMatches[1]
			secretValue := content[secretStart:secretEnd]

			// Calculate line numbers
			linesBeforeStart := strings.Count(content[:secretStart], "\n") + 1
			linesBeforeEnd := strings.Count(content[:secretEnd], "\n") + 1

			confidence := calculateConfidenceScore(secretValue, secretValue, false)
			if confidence < 50 {
				log.Printf("Skipped low-confidence multiline secret at %s:%d: %s (Confidence: %.2f)", fileInfo.Filename, linesBeforeStart, truncateSecretValue(secretValue), confidence)
				continue
			}

			secrets = append(secrets, Secret{
				ProjectKey:     fileInfo.ProjectKey,
				RepositorySlug: fileInfo.RepositorySlug,
				CommitID:       fileInfo.CommitID,
				CommitDate:     fileInfo.CommitDate,
				CommitAuthor:   fileInfo.CommitAuthor,
				Filename:       fileInfo.Filename,
				LineNumber:     linesBeforeStart,
				EndLine:        linesBeforeEnd,
				SecretType:     secretType,
				SecretValue:    truncateSecretValue(secretValue),
				Confidence:     confidence,
			})

			regions = append(regions, Region{
				StartLine: linesBeforeStart,
				EndLine:   linesBeforeEnd,
			})
		}
	}

	return secrets, regions
}

// truncateSecretValue truncates long secret values for the CSV output
func truncateSecretValue(value string) string {
	// Keep only first and last line for multi-line secrets
	lines := strings.Split(value, "\n")
	if len(lines) > 2 {
		return lines[0] + "\n...[truncated]...\n" + lines[len(lines)-1]
	}
	return value
}

// DirectoryScanner scans directories for secrets
type DirectoryScanner struct {
	fileScanner *FileScanner
}

// NewDirectoryScanner creates a new directory scanner
func NewDirectoryScanner(detector *SecretDetector) *DirectoryScanner {
	return &DirectoryScanner{
		fileScanner: NewFileScanner(detector),
	}
}

// ScanDirectory scans all files in a directory for secrets
func (s *DirectoryScanner) ScanDirectory(dirPath string) ([]Secret, error) {
	files, err := util.ListFilesInDirectory(dirPath)
	if err != nil {
		return nil, err
	}

	var allSecrets []Secret
	for _, filePath := range files {
		secrets, err := s.fileScanner.ScanFile(filePath)
		if err != nil {
			log.Printf("Error scanning %s: %v", filePath, err)
			continue
		}
		allSecrets = append(allSecrets, secrets...)
	}

	return allSecrets, nil
}

// BitbucketScanner scans Bitbucket repositories for secrets
type BitbucketScanner struct {
	client   *bitbucket.Client
	detector *SecretDetector
}

// NewBitbucketScanner creates a new Bitbucket scanner
func NewBitbucketScanner(client *bitbucket.Client, detector *SecretDetector) *BitbucketScanner {
	return &BitbucketScanner{
		client:   client,
		detector: detector,
	}
}

// ScanBitbucketFile scans a single file in a Bitbucket repository
func (s *BitbucketScanner) ScanBitbucketFile(projectKey, repoSlug, commitID, filePath string, commit bitbucket.Commit) ([]Secret, error) {
	content, err := s.client.GetFileContent(projectKey, repoSlug, commitID, filePath)
	if err != nil {
		return nil, err
	}

	// Format date for output
	commitDate := ""
	if commit.Date != "" {
		timestamp, err := time.Parse(time.RFC3339, commit.Date)
		if err == nil {
			commitDate = timestamp.Format("2006-01-02 15:04:05")
		}
	}

	// Format author for output
	commitAuthor := ""
	if commit.AuthorObj.Name != "" {
		commitAuthor = commit.AuthorObj.Name
		if commit.AuthorObj.Email != "" {
			commitAuthor += " <" + commit.AuthorObj.Email + ">"
		}
	}

	fileInfo := SecretFileInfo{
		ProjectKey:     projectKey,
		RepositorySlug: repoSlug,
		CommitID:       commitID,
		CommitDate:     commitDate,
		CommitAuthor:   commitAuthor,
		Filename:       filePath,
	}

	// First, scan for multi-line secrets (prioritizing private keys)
	multilineSecrets, privateKeyRegions := s.scanMultilineSecrets(content, fileInfo)

	// Then scan line by line for single-line secrets, skipping private key regions
	var singleLineSecrets []Secret
	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Skip lines that are part of a private key region
		if isLineInPrivateKeyRegion(lineNum, privateKeyRegions) {
			continue
		}

		lineSecrets := s.detector.DetectSecrets(line, lineNum, fileInfo)
		for _, secret := range lineSecrets {
			if secret.Confidence < 50 {
				log.Printf("Skipped low-confidence secret at %s:%d: %s (Confidence: %.2f)", fileInfo.Filename, lineNum, secret.SecretValue, secret.Confidence)
				continue
			}
			singleLineSecrets = append(singleLineSecrets, secret)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Combine all secrets
	allSecrets := append(singleLineSecrets, multilineSecrets...)

	// Output as JSON
	jsonOutput, err := json.MarshalIndent(allSecrets, "", "  ")
	if err == nil {
		log.Printf("Secrets found in %s: %s", fileInfo.Filename, string(jsonOutput))
	}

	return allSecrets, nil
}

// scanMultilineSecrets scans for secrets that span multiple lines in Bitbucket files
func (s *BitbucketScanner) scanMultilineSecrets(content string, fileInfo SecretFileInfo) ([]Secret, []Region) {
	var secrets []Secret
	var privateKeyRegions []Region

	// Detect SSH Private Keys
	sshPrivateKeys, regions := detectMultilineSecret(
		content,
		"-----BEGIN OPENSSH PRIVATE KEY-----",
		"-----END OPENSSH PRIVATE KEY-----",
		"SSH Private Key",
		fileInfo,
	)
	secrets = append(secrets, sshPrivateKeys...)
	privateKeyRegions = append(privateKeyRegions, regions...)

	// Detect RSA Private Keys
	rsaPrivateKeys, regions := detectMultilineSecret(
		content,
		"-----BEGIN RSA PRIVATE KEY-----",
		"-----END RSA PRIVATE KEY-----",
		"RSA Private Key",
		fileInfo,
	)
	secrets = append(secrets, rsaPrivateKeys...)
	privateKeyRegions = append(privateKeyRegions, regions...)

	// Detect PGP Private Keys
	pgpPrivateKeys, regions := detectMultilineSecret(
		content,
		"-----BEGIN PGP PRIVATE KEY BLOCK-----",
		"-----END PGP PRIVATE KEY BLOCK-----",
		"PGP Private Key",
		fileInfo,
	)
	secrets = append(secrets, pgpPrivateKeys...)
	privateKeyRegions = append(privateKeyRegions, regions...)

	// Detect EC Private Keys
	ecPrivateKeys, regions := detectMultilineSecret(
		content,
		"-----BEGIN EC PRIVATE KEY-----",
		"-----END EC PRIVATE KEY-----",
		"EC Private Key",
		fileInfo,
	)
	secrets = append(secrets, ecPrivateKeys...)
	privateKeyRegions = append(privateKeyRegions, regions...)

	// Detect PRIVATE KEYs (generic)
	genericPrivateKeys, regions := detectMultilineSecret(
		content,
		"-----BEGIN PRIVATE KEY-----",
		"-----END PRIVATE KEY-----",
		"Private Key",
		fileInfo,
	)
	secrets = append(secrets, genericPrivateKeys...)
	privateKeyRegions = append(privateKeyRegions, regions...)

	return secrets, privateKeyRegions
}
