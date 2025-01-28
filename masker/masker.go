package masker

import (
	"regexp"
	"strings"
)

// Compile regex patterns once at package initialization
var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)password\s*[:=]\s*([^\s]+)`),
	regexp.MustCompile(`(?i)api_key\s*[:=]\s*([^\s]+)`),
	regexp.MustCompile(`(?i)token\s*[:=]\s*([^\s]+)`),
	regexp.MustCompile(`[a-zA-Z0-9]{32}`),
	regexp.MustCompile(`[a-zA-Z0-9]{40}`),
	regexp.MustCompile(`[a-zA-Z0-9]{64}`),
	regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`),
	regexp.MustCompile(`(?i)bearer\s+([a-zA-Z0-9._-]+)`),
	regexp.MustCompile(`\$(?:[A-Z_][A-Z0-9_]*)`),
	regexp.MustCompile(`\$\{(?:[A-Z_][A-Z0-9_]*)\}`),
	regexp.MustCompile(`\%(?:[A-Z_][A-Z0-9_]*)\%`),
	regexp.MustCompile(`(?i)[A-Z_][A-Z0-9_]*\s*=\s*([^\s]+)`),
}

/*
Mask masks detected credentials in the input text

Here is a sample text with credentials:
  - password: mysecretpassword
  - api_key: 1234567890abcdef1234567890abcdef
  - token: abcdef1234567890abcdef1234567890abcdef12
  - UUID: 123e4567-e89b-12d3-a456-426614174000
  - Bearer token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
  - URL: https://example.com?token=notamask
  - SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  - Env var (Unix): $API_KEY
  - Env var (Unix with braces): ${DATABASE_URL}
  - Env var (Windows): %SECRET_TOKEN%
  - Key-value pair: DEEPSEEK_API_KEY=sk-8a65d84eb9e6
*/
func Mask(text string) string {
	return maskCredentials(text)
}

// TODO: Optimize and add more patterns
func maskCredentials(text string) string {
	// Mask detected credentials using precompiled patterns
	for _, re := range credentialPatterns {
		text = re.ReplaceAllStringFunc(text, func(match string) string {
			// Skip masking if the match is part of a URL or common non-credential text
			if strings.Contains(match, "://") || strings.Contains(match, ".") {
				return match
			}

			// For key-value pairs, only mask the value part
			if strings.Contains(match, ":") || strings.Contains(match, "=") {
				parts := strings.SplitN(match, ":", 2)
				if len(parts) == 2 {
					return parts[0] + ": *****"
				}
				parts = strings.SplitN(match, "=", 2)
				if len(parts) == 2 {
					return parts[0] + "= *****"
				}
			}

			return "[*****SENSITIVE_DATA*****]" // Mask the credential
		})
	}

	return text
}
