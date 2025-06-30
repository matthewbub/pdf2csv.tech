package utils

import (
	"testing"
	"time"
)

func TestBlacklistToken(t *testing.T) {
	// Set up test environment
	if err := SetTestEnvironment(); err != nil {
		t.Fatalf("Failed to set test environment: %v", err)
	}

	// Run test migrations
	if err := RunMigrationsTest(); err != nil {
		t.Fatalf("Failed to run test migrations: %v", err)
	}

	db := GetDB()
	if db == nil {
		t.Fatal("Failed to get database connection")
	}

	// Generate a test token
	userID := "test-user-123"
	token, err := GenerateJWT(userID)
	if err != nil {
		t.Fatalf("Failed to generate JWT: %v", err)
	}

	// Initially, token should not be blacklisted
	isBlacklisted, err := IsTokenBlacklisted(db, token)
	if err != nil {
		t.Fatalf("Failed to check token blacklist status: %v", err)
	}
	if isBlacklisted {
		t.Error("Token should not be blacklisted initially")
	}

	// Blacklist the token
	err = BlacklistToken(db, token, "test_revocation")
	if err != nil {
		t.Fatalf("Failed to blacklist token: %v", err)
	}

	// Now token should be blacklisted
	isBlacklisted, err = IsTokenBlacklisted(db, token)
	if err != nil {
		t.Fatalf("Failed to check token blacklist status after blacklisting: %v", err)
	}
	if !isBlacklisted {
		t.Error("Token should be blacklisted after blacklisting")
	}

	// Test blacklisting the same token again (should not error)
	err = BlacklistToken(db, token, "test_revocation_duplicate")
	if err != nil {
		t.Fatalf("Failed to blacklist token again: %v", err)
	}
}

func TestBlacklistAllUserTokens(t *testing.T) {
	// Set up test environment
	if err := SetTestEnvironment(); err != nil {
		t.Fatalf("Failed to set test environment: %v", err)
	}

	// Run test migrations
	if err := RunMigrationsTest(); err != nil {
		t.Fatalf("Failed to run test migrations: %v", err)
	}

	db := GetDB()
	if db == nil {
		t.Fatal("Failed to get database connection")
	}

	userID := "test-user-456"

	// Generate multiple tokens for the user
	accessToken, err := GenerateJWT(userID)
	if err != nil {
		t.Fatalf("Failed to generate access token: %v", err)
	}

	refreshToken, err := GenerateRefreshToken(userID)
	if err != nil {
		t.Fatalf("Failed to generate refresh token: %v", err)
	}

	// Initially, tokens should not be blacklisted
	isAccessBlacklisted, err := IsTokenBlacklisted(db, accessToken)
	if err != nil {
		t.Fatalf("Failed to check access token blacklist status: %v", err)
	}
	if isAccessBlacklisted {
		t.Error("Access token should not be blacklisted initially")
	}

	isRefreshBlacklisted, err := IsTokenBlacklisted(db, refreshToken)
	if err != nil {
		t.Fatalf("Failed to check refresh token blacklist status: %v", err)
	}
	if isRefreshBlacklisted {
		t.Error("Refresh token should not be blacklisted initially")
	}

	// Blacklist all tokens for the user
	err = BlacklistAllUserTokens(db, userID, "user_logout_all_devices")
	if err != nil {
		t.Fatalf("Failed to blacklist all user tokens: %v", err)
	}

	// Check that a global blacklist entry was created
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM token_blacklist WHERE user_id = ? AND token_type = 'all'", userID).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to check global blacklist entry: %v", err)
	}
	if count == 0 {
		t.Error("Global blacklist entry should be created for user")
	}
}

func TestCleanupExpiredBlacklistedTokens(t *testing.T) {
	// Set up test environment
	if err := SetTestEnvironment(); err != nil {
		t.Fatalf("Failed to set test environment: %v", err)
	}

	// Run test migrations
	if err := RunMigrationsTest(); err != nil {
		t.Fatalf("Failed to run test migrations: %v", err)
	}

	db := GetDB()
	if db == nil {
		t.Fatal("Failed to get database connection")
	}

	// Insert an expired blacklisted token directly into the database
	expiredTime := time.Now().Add(-24 * time.Hour) // 24 hours ago
	_, err := db.Exec(`
		INSERT INTO token_blacklist (token_jti, user_id, token_type, expires_at, reason)
		VALUES (?, ?, ?, ?, ?)
	`, "expired-jti-123", "test-user-789", "access", expiredTime, "test_expired")
	if err != nil {
		t.Fatalf("Failed to insert expired token: %v", err)
	}

	// Insert a non-expired blacklisted token
	futureTime := time.Now().Add(24 * time.Hour) // 24 hours from now
	_, err = db.Exec(`
		INSERT INTO token_blacklist (token_jti, user_id, token_type, expires_at, reason)
		VALUES (?, ?, ?, ?, ?)
	`, "valid-jti-456", "test-user-789", "access", futureTime, "test_valid")
	if err != nil {
		t.Fatalf("Failed to insert valid token: %v", err)
	}

	// Check initial count
	var initialCount int
	err = db.QueryRow("SELECT COUNT(*) FROM token_blacklist").Scan(&initialCount)
	if err != nil {
		t.Fatalf("Failed to get initial count: %v", err)
	}

	// Run cleanup
	err = CleanupExpiredBlacklistedTokens(db)
	if err != nil {
		t.Fatalf("Failed to cleanup expired tokens: %v", err)
	}

	// Check final count (should be one less)
	var finalCount int
	err = db.QueryRow("SELECT COUNT(*) FROM token_blacklist").Scan(&finalCount)
	if err != nil {
		t.Fatalf("Failed to get final count: %v", err)
	}

	if finalCount != initialCount-1 {
		t.Errorf("Expected final count to be %d, got %d", initialCount-1, finalCount)
	}

	// Verify the expired token was removed
	var expiredCount int
	err = db.QueryRow("SELECT COUNT(*) FROM token_blacklist WHERE token_jti = ?", "expired-jti-123").Scan(&expiredCount)
	if err != nil {
		t.Fatalf("Failed to check expired token: %v", err)
	}
	if expiredCount != 0 {
		t.Error("Expired token should have been removed")
	}

	// Verify the valid token remains
	var validCount int
	err = db.QueryRow("SELECT COUNT(*) FROM token_blacklist WHERE token_jti = ?", "valid-jti-456").Scan(&validCount)
	if err != nil {
		t.Fatalf("Failed to check valid token: %v", err)
	}
	if validCount != 1 {
		t.Error("Valid token should remain in blacklist")
	}
}

func TestIsTokenBlacklisted_InvalidToken(t *testing.T) {
	// Set up test environment
	if err := SetTestEnvironment(); err != nil {
		t.Fatalf("Failed to set test environment: %v", err)
	}

	// Run test migrations
	if err := RunMigrationsTest(); err != nil {
		t.Fatalf("Failed to run test migrations: %v", err)
	}

	db := GetDB()
	if db == nil {
		t.Fatal("Failed to get database connection")
	}

	// Test with malformed token
	isBlacklisted, err := IsTokenBlacklisted(db, "invalid.token.here")
	if err == nil {
		t.Error("Expected error for malformed token")
	}
	if isBlacklisted {
		t.Error("Malformed token should not be considered blacklisted")
	}

	// Test with token without JTI
	tokenWithoutJTI := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoidGVzdCIsImV4cCI6OTk5OTk5OTk5OX0.invalid"
	isBlacklisted, err = IsTokenBlacklisted(db, tokenWithoutJTI)
	if err != nil {
		t.Errorf("Should not error for token without JTI: %v", err)
	}
	if isBlacklisted {
		t.Error("Token without JTI should not be considered blacklisted")
	}
}
