package utils

import (
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"bus.zcauldron.com/pkg/constants"
	"github.com/joho/godotenv"
)

func init() {
	// Load .env file if it exists
	godotenv.Load()
}

func GetSecretKeyFromEnv() []byte {
	key := os.Getenv("SESSION_SECRET_KEY")
	if key == "" {
		log.Fatal("SESSION_SECRET_KEY environment variable is not set")
	}
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		log.Fatal("Failed to decode SESSION_SECRET_KEY:", err)
	}
	return decoded
}

func GetEnv() string {
	env := os.Getenv("ENV")
	logger := GetLogger()
	if env == "" {
		logger.Printf("ENV environment variable is not set")
	}
	return env
}

func ValidateEnvironment() error {
	env := GetEnv()
	if env == "" {
		return fmt.Errorf("ENV is not set")
	}

	// define valid environments
	validEnvironments := []string{
		constants.ENV_PRODUCTION,
		constants.ENV_DEVELOPMENT,
		constants.ENV_TEST,
		constants.ENV_STAGING,
	}

	// check if the current environment is valid
	isValid := false
	for _, validEnv := range validEnvironments {
		if env == validEnv {
			isValid = true
			break
		}
	}

	if !isValid {
		return fmt.Errorf("ENV is not valid")
	}

	// add other environment checks here
	return nil
}

func SetTestEnvironment() error {
	// Try to load .env file from project root (go up directories until we find it)
	envPaths := []string{
		".env",           // current directory
		"../.env",        // one level up
		"../../.env",     // two levels up (for nested packages)
		"../../../.env",  // three levels up
	}
	
	for _, path := range envPaths {
		if err := godotenv.Load(path); err == nil {
			break // Successfully loaded .env file
		}
	}

	testKey := os.Getenv("TEST_SESSION_SECRET_KEY")
	if testKey == "" {
		return fmt.Errorf("TEST_SESSION_SECRET_KEY is not set")
	}

	// validate the test key format
	if _, err := base64.StdEncoding.DecodeString(testKey); err != nil {
		return fmt.Errorf("invalid TEST_SESSION_SECRET_KEY format: %w", err)
	}

	os.Setenv("ENV", "test")
	os.Setenv("SESSION_SECRET_KEY", testKey)
	return nil
}
