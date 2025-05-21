package scanner

import (
	"encoding/base64"
	"math"
	"regexp"
	"strings"
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

// calculateEntropy calculates the Shannon entropy of a string
func calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	entropy := 0.0
	length := float64(len(s))
	for _, count := range freq {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// calculateCharacterDiversity calculates the ratio of unique characters
func calculateCharacterDiversity(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	unique := make(map[rune]bool)
	for _, r := range s {
		unique[r] = true
	}
	return float64(len(unique)) / float64(len(s))
}

// isDictionaryWord checks if the string contains common test words
func isDictionaryWord(s string) bool {
	lower := strings.ToLower(s)
	testWords := []string{"test", "example", "dummy", "fake", "not_a_real", "sample"}
	for _, word := range testWords {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}

// calculateConfidenceScore computes a confidence score for a secret
func calculateConfidenceScore(secretValue, line string, isQuoted bool) float64 {
	score := 0.0

	// Entropy (0–30 points)
	entropy := calculateEntropy(secretValue)
	if entropy > 4.0 {
		score += 30
	} else if entropy > 3.0 {
		score += 20
	} else if entropy > 2.0 {
		score += 10
	}

	// Character diversity (0–20 points)
	diversity := calculateCharacterDiversity(secretValue)
	if diversity > 0.7 {
		score += 20
	} else if diversity > 0.5 {
		score += 10
	}

	// Contextual keywords (0–30 points)
	contextKeywords := []string{"secret", "token", "key", "auth", "password", "credential"}
	for _, keyword := range contextKeywords {
		if strings.Contains(strings.ToLower(line), keyword) {
			score += 10
			break
		}
	}

	// Quoting (0–10 points)
	if isQuoted {
		score += 10
	}

	// Dictionary word penalty (-20 points)
	if isDictionaryWord(secretValue) {
		score -= 20
	}

	// Length bonus (0–10 points)
	if len(secretValue) > 20 {
		score += 10
	} else if len(secretValue) > 10 {
		score += 5
	}

	return math.Max(0, math.Min(100, score))
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
				if len(match) > 1 && match[1] != "" {
					secretValue = match[1]
				}
				if len(secretValue) < 6 {
					continue
				}
				confidence := calculateConfidenceScore(secretValue, line, false)
				if confidence < 50 {
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
					Confidence:     confidence,
				})
				return secrets
			}
		}
	}

	// Check for Base64-encoded secrets
	if pattern, exists := d.patterns["Base64 Potential"]; exists {
		matches := pattern.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			encoded := match[0]
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err == nil {
				decodedLine := string(decoded)
				// Recursively scan the decoded string
				decodedSecrets := d.DetectSecrets(decodedLine, lineNum, fileInfo)
				for i := range decodedSecrets {
					decodedSecrets[i].SecretType = "Base64 Decoded " + decodedSecrets[i].SecretType
				}
				secrets = append(secrets, decodedSecrets...)
			}
		}
	}

	// Check other patterns
	for secretType, pattern := range d.patterns {
		isPrivateKey := false
		for _, pkType := range privateKeyTypes {
			if secretType == pkType || secretType == "Base64 Potential" {
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
			if len(match) > 1 && match[1] != "" {
				secretValue = match[1]
			}
			if len(secretValue) < 6 {
				continue
			}

			// Skip unquoted values with dots or code-like patterns unless in comments
			if secretType != "Comment Secret" && !strings.ContainsAny(secretValue, "'\"") && strings.Contains(secretValue, ".") {
				continue
			}

			// Calculate confidence score
			isQuoted := strings.HasPrefix(secretValue, "'") || strings.HasPrefix(secretValue, "\"")
			confidence := calculateConfidenceScore(secretValue, line, isQuoted)
			if confidence < 50 {
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
				Confidence:     confidence,
			})
		}
	}

	return secrets
}
