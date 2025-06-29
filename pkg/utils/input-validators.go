package utils

import (
	"html"
	"regexp"
	"strings"
)

func MustBe8Characters(password string) bool {
	return len(password) >= 8
}

func MustContainUppercase(password string) bool {
	return strings.ContainsAny(password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

func MustContainLowercase(password string) bool {
	return strings.ContainsAny(password, "abcdefghijklmnopqrstuvwxyz")
}

func MustContainNumber(password string) bool {
	return strings.ContainsAny(password, "0123456789")
}

func MustContainSpecialCharacter(password string) bool {
	return strings.ContainsAny(password, "!@#$%^&*()_+-=[]{}|;:,.<>?")
}

func SanitizeInput(input string) string {
	// Escape HTML to prevent XSS
	return html.EscapeString(strings.TrimSpace(input))
}

func IsValidUsername(username string) bool {
	// Example validation: username must be alphanumeric and 3-20 characters long
	re := regexp.MustCompile(`^[a-zA-Z0-9._-]{3,30}$`)
	return re.MatchString(username)
}

func IsValidEmail(email string) bool {
	// Basic email validation - reject emails with control characters
	if strings.ContainsAny(email, "\n\r\t\x00") {
		return false
	}

	re := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return re.MatchString(email)
}

// MaxLength returns true if the input is less than or equal to the max length.
func MaxLength(input string, maxLength int) bool {
	return len(input) <= maxLength
}
