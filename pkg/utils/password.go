package utils

import (
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func ValidatePasswordStrength(password string) error {
	if !MaxLength(password, 72) {
		return fmt.Errorf("password must be less than 72 characters")
	}
	if !MustBe8Characters(password) {
		return fmt.Errorf("password must be at least 8 characters")
	}
	if !MustContainUppercase(password) {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !MustContainLowercase(password) {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !MustContainNumber(password) {
		return fmt.Errorf("password must contain at least one number")
	}
	if !MustContainSpecialCharacter(password) {
		return fmt.Errorf("password must contain at least one special character")
	}
	return nil
}
