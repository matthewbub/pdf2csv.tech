package utils

import (
	"testing"
	"time"
)

func TestGenerateRefreshToken(t *testing.T) {
	userID := "test-user-123"

	token, err := GenerateRefreshToken(userID)
	if err != nil {
		t.Fatalf("Failed to generate refresh token: %v", err)
	}

	if token == "" {
		t.Fatal("Generated refresh token is empty")
	}

	// Verify the token can be verified
	extractedUserID, expTime, err := VerifyRefreshToken(token)
	if err != nil {
		t.Fatalf("Failed to verify refresh token: %v", err)
	}

	if extractedUserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, extractedUserID)
	}

	if expTime.Before(time.Now()) {
		t.Error("Refresh token should not be expired")
	}
}

func TestGenerateTokenPair(t *testing.T) {
	userID := "test-user-456"

	accessToken, refreshToken, err := GenerateTokenPair(userID)
	if err != nil {
		t.Fatalf("Failed to generate token pair: %v", err)
	}

	if accessToken == "" {
		t.Fatal("Generated access token is empty")
	}

	if refreshToken == "" {
		t.Fatal("Generated refresh token is empty")
	}

	// Verify both tokens
	accessUserID, _, err := VerifyJWT(accessToken)
	if err != nil {
		t.Fatalf("Failed to verify access token: %v", err)
	}

	refreshUserID, _, err := VerifyRefreshToken(refreshToken)
	if err != nil {
		t.Fatalf("Failed to verify refresh token: %v", err)
	}

	if accessUserID != userID {
		t.Errorf("Expected access token user ID %s, got %s", userID, accessUserID)
	}

	if refreshUserID != userID {
		t.Errorf("Expected refresh token user ID %s, got %s", userID, refreshUserID)
	}
}

func TestVerifyRefreshToken_InvalidType(t *testing.T) {
	userID := "test-user-789"

	// Generate an access token (not a refresh token)
	accessToken, err := GenerateJWT(userID)
	if err != nil {
		t.Fatalf("Failed to generate access token: %v", err)
	}

	// Try to verify it as a refresh token - should fail
	_, _, err = VerifyRefreshToken(accessToken)
	if err == nil {
		t.Fatal("Expected error when verifying access token as refresh token")
	}

	if err.Error() != "invalid token type: expected refresh token" {
		t.Errorf("Expected specific error message, got: %v", err)
	}
}
