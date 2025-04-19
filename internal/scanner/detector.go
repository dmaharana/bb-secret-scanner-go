package scanner

import (
	"regexp"
)

// SecretDetector contains the logic to detect secrets
type SecretDetector struct {
	patterns map[string]*regexp.Regexp
}

// NewSecretDetector creates a new secret detector with predefined patterns
func NewSecretDetector() *SecretDetector {
	return &SecretDetector{
		patterns: getSecretPatterns(),
	}
}

// DetectSecrets scans a line for secrets
func (d *SecretDetector) DetectSecrets(line string, lineNum int, fileInfo SecretFileInfo) []Secret {
	var secrets []Secret

	// Define private key patterns to check first
	privateKeyTypes := []string{
		"Private Key",
		"SSH Private Key",
		"RSA Private Key",
		"PGP Private Key",
		"EC Private Key",
	}

	// Check for private keys first
	for _, secretType := range privateKeyTypes {
		if pattern, exists := d.patterns[secretType]; exists {
			matches := pattern.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				secretValue := match[0]
				// If the pattern has a capturing group, use that for the value
				if len(match) > 1 && match[1] != "" {
					secretValue = match[1]
				}

				// Avoid false positives with empty or too short matches
				if len(secretValue) < 8 {
					continue
				}

				secrets = append(secrets, Secret{
					ProjectKey:     fileInfo.ProjectKey,
					RepositorySlug: fileInfo.RepositorySlug,
					CommitID:       fileInfo.CommitID,
					CommitDate:     fileInfo.CommitDate,
					CommitAuthor:   fileInfo.CommitAuthor,
					Filename:       fileInfo.Filename,
					LineNumber:     lineNum,
					SecretType:     secretType,
					SecretValue:    secretValue,
				})

				// If a private key is detected, return immediately
				return secrets
			}
		}
	}

	// If no private key is detected, check other patterns
	for secretType, pattern := range d.patterns {
		// Skip private key patterns since they were already checked
		isPrivateKey := false
		for _, pkType := range privateKeyTypes {
			if secretType == pkType {
				isPrivateKey = true
				break
			}
		}
		if isPrivateKey {
			continue
		}

		matches := pattern.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			secretValue := match[0]
			// If the pattern has a capturing group, use that for the value
			if len(match) > 1 && match[1] != "" {
				secretValue = match[1]
			}

			// Avoid false positives with empty or too short matches
			if len(secretValue) < 8 {
				continue
			}

			secrets = append(secrets, Secret{
				ProjectKey:     fileInfo.ProjectKey,
				RepositorySlug: fileInfo.RepositorySlug,
				CommitID:       fileInfo.CommitID,
				CommitDate:     fileInfo.CommitDate,
				CommitAuthor:   fileInfo.CommitAuthor,
				Filename:       fileInfo.Filename,
				LineNumber:     lineNum,
				SecretType:     secretType,
				SecretValue:    secretValue,
			})
		}
	}

	return secrets
}
