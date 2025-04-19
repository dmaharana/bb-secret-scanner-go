package scanner

import (
	"bufio"
	"os"
	"strings"
	"time"

	"bitbucket-secrets-scanner/internal/bitbucket"
	"bitbucket-secrets-scanner/pkg/util"
)

// Secret represents a detected secret in a file
type Secret struct {
	ProjectKey     string
	RepositorySlug string
	CommitID       string
	CommitDate     string
	CommitAuthor   string
	Filename       string
	LineNumber     int
	SecretType     string
	SecretValue    string
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

// ScanFile scans a single file for secrets
func (s *FileScanner) ScanFile(filePath string) ([]Secret, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fileInfo := SecretFileInfo{
		ProjectKey:     "local",
		RepositorySlug: "local",
		CommitID:       "local",
		CommitDate:     time.Now().Format("2006-01-02 15:04:05"),
		CommitAuthor:   "local",
		Filename:       filePath,
	}

	return s.scanContent(file, fileInfo)
}

// scanContent scans the content of a reader for secrets
func (s *FileScanner) scanContent(file *os.File, fileInfo SecretFileInfo) ([]Secret, error) {
	var secrets []Secret
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		lineSecrets := s.detector.DetectSecrets(line, lineNum, fileInfo)
		secrets = append(secrets, lineSecrets...)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return secrets, nil
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
			// Log error but continue with next file
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

	var secrets []Secret
	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		lineSecrets := s.detector.DetectSecrets(line, lineNum, fileInfo)
		secrets = append(secrets, lineSecrets...)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return secrets, nil
}
