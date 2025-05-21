package scanner

import (
	"regexp"
)

// getSecretPatterns returns a map of regex patterns for detecting secrets
func getSecretPatterns() map[string]*regexp.Regexp {
	return map[string]*regexp.Regexp{
		"AWS Access Key":        regexp.MustCompile(`(?i)\bAKIA[0-9A-Z]{16}\b`),
		"AWS Secret Key":        regexp.MustCompile(`(?i)\b[0-9a-zA-Z/+]{40}\b`),
		"GitHub Token":          regexp.MustCompile(`(?i)(?:secret|token|key|auth|github)[^\s=:]*\s*[:=]\s*['"]([0-9a-zA-Z]{35,40})['"]`),
		"Generic API Key":       regexp.MustCompile(`(?i)(?:secret|token|key|auth|api[_\-\.]?key|apikey)[^\s=:]*\s*[:=]\s*['"]([0-9a-zA-Z!@#$%^&*_-]{16,45})['"]`),
		"Password Assignment":   regexp.MustCompile(`(?i)(?:secret|password|passwd|pwd)[^\s=:]*\s*[:=]\s*['"]([0-9a-zA-Z!@#$%^&*_-]{6,40})['"]`),
		"Private Key":           regexp.MustCompile(`(?i)-----BEGIN .*? PRIVATE KEY-----\z`),
		"Connection String":     regexp.MustCompile(`(?i)(mongodb|mysql|postgresql|postgres)://[^\s<'"]+`),
		"JWT Token":             regexp.MustCompile(`(?i)ey[0-9a-zA-Z\._-]{10,}\.[0-9a-zA-Z\._-]{10,}\.[0-9a-zA-Z\._-]{10,}`),
		"Google API Key":        regexp.MustCompile(`(?i)AIza[0-9A-Za-z\-_]{35}`),
		"Slack Token":           regexp.MustCompile(`(?i)xox[baprs]-[0-9a-zA-Z]{10,48}`),
		"Stripe API Key":        regexp.MustCompile(`(?i)sk_live_[0-9a-zA-Z]{24}`),
		"Square Access Token":   regexp.MustCompile(`(?i)sq0atp-[0-9A-Za-z\-_]{22}`),
		"Square OAuth Secret":   regexp.MustCompile(`(?i)sq0csp-[0-9A-Za-z\-_]{43}`),
		"Twilio API Key":        regexp.MustCompile(`(?i)SK[0-9a-fA-F]{32}`),
		"SSH Private Key":       regexp.MustCompile(`(?i)-----BEGIN OPENSSH PRIVATE KEY-----`),
		"PGP Private Key":       regexp.MustCompile(`(?i)-----BEGIN PGP PRIVATE KEY BLOCK-----`),
		"Facebook Access Token": regexp.MustCompile(`(?i)EAACEdEose0cBA[0-9A-Za-z]+`),
		"Twitter Access Token":  regexp.MustCompile(`(?i)[1-9][0-9]+-[0-9a-zA-Z]{40}`),
		"Comment Secret":        regexp.MustCompile(`(?i)#.*?(?:secret|password|passwd|pwd|api[_\-\.]?key|token|key|auth)\s*[:=]\s*['"]([0-9a-zA-Z!@#$%^&*_-]{6,40})['"]`),
		"Base64 Potential":      regexp.MustCompile(`(?i)\b[A-Za-z0-9+/=]{20,}\b`),
	}
}
