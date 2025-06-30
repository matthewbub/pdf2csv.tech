package utils

import (
	"os"
	"testing"
	"time"

	"bus.zcauldron.com/pkg/constants"
)

func TestGetCookieConfig(t *testing.T) {
	// Save original environment
	originalEnv := os.Getenv("ENV")
	defer func() {
		// Reset environment after test
		if originalEnv != "" {
			os.Setenv("ENV", originalEnv)
		} else {
			os.Unsetenv("ENV")
		}
	}()

	// Test production environment
	os.Setenv("ENV", constants.ENV_PRODUCTION)
	config := GetCookieConfig(time.Hour)

	if config.Expiration != time.Hour {
		t.Errorf("Expected expiration to be %v, got %v", time.Hour, config.Expiration)
	}

	if config.Domain != constants.AppConfig.ProductionDomain {
		t.Errorf("Expected domain to be %s, got %s", constants.AppConfig.ProductionDomain, config.Domain)
	}

	if !config.Secure {
		t.Error("Expected Secure to be true for production")
	}

	if !config.HttpOnly {
		t.Error("Expected HttpOnly to be true for production")
	}

	// Test development environment
	os.Setenv("ENV", constants.ENV_DEVELOPMENT)
	config = GetCookieConfig(time.Hour)

	if config.Secure {
		t.Error("Expected Secure to be false for development")
	}

	if config.HttpOnly {
		t.Error("Expected HttpOnly to be false for development")
	}

	// Test with negative expiration (for clearing cookies)
	config = GetCookieConfig(-1)
	if config.Expiration != -1 {
		t.Errorf("Expected expiration to be -1, got %v", config.Expiration)
	}
}
