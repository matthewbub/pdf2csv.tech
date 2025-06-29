package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestMain(m *testing.M) {
	// Set test environment
	if err := SetTestEnvironment(); err != nil {
		panic(err)
	}
	exitCode := m.Run()
	os.Exit(exitCode)
}

func TestGenerateJWT(t *testing.T) {
	userID := "test-user-123"

	token, err := GenerateJWT(userID)
	if err != nil {
		t.Fatalf("Failed to generate JWT: %v", err)
	}

	if token == "" {
		t.Fatal("Generated token is empty")
	}

	// Verify the token uses HS256
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			t.Errorf("Expected HS256 signing method, got %v", token.Method)
		}
		return []byte(GetSecretKeyFromEnv()), nil
	})

	if err != nil {
		t.Fatalf("Failed to parse generated token: %v", err)
	}

	if !parsedToken.Valid {
		t.Fatal("Generated token is not valid")
	}
}

func TestVerifyJWT_ValidToken(t *testing.T) {
	userID := "test-user-123"

	// Generate a valid token
	token, err := GenerateJWT(userID)
	if err != nil {
		t.Fatalf("Failed to generate JWT: %v", err)
	}

	// Verify the token
	extractedUserID, expTime, err := VerifyJWT(token)
	if err != nil {
		t.Fatalf("Failed to verify valid JWT: %v", err)
	}

	if extractedUserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, extractedUserID)
	}

	if expTime.Before(time.Now()) {
		t.Error("Token expiration time is in the past")
	}
}

func TestVerifyJWT_InvalidAlgorithm_RS256(t *testing.T) {
	// Generate RSA key pair for RS256 token
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create a token with RS256 algorithm
	claims := jwt.MapClaims{
		"user_id": "test-user-123",
		"exp":     time.Now().Add(time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign RS256 token: %v", err)
	}

	// Attempt to verify the RS256 token - should fail
	_, _, err = VerifyJWT(tokenString)
	if err == nil {
		t.Fatal("Expected error when verifying RS256 token, but got none")
	}

	expectedError := "unexpected signing method: only HS256 is allowed"
	if !strings.Contains(err.Error(), expectedError) {
		t.Errorf("Expected error to contain '%s', got '%s'", expectedError, err.Error())
	}
}

func TestVerifyJWT_InvalidAlgorithm_None(t *testing.T) {
	// Create a token with "none" algorithm (no signature)
	claims := jwt.MapClaims{
		"user_id": "test-user-123",
		"exp":     time.Now().Add(time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("Failed to sign 'none' token: %v", err)
	}

	// Attempt to verify the 'none' token - should fail
	_, _, err = VerifyJWT(tokenString)
	if err == nil {
		t.Fatal("Expected error when verifying 'none' algorithm token, but got none")
	}
}

func TestJwtSecretKeyFunc_ValidHS256(t *testing.T) {
	// Create a token with HS256
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{})

	secret, err := jwtSecretKeyFunc(token)
	if err != nil {
		t.Fatalf("Expected no error for HS256 token, got: %v", err)
	}

	expectedSecret := []byte(GetSecretKeyFromEnv())
	if string(secret.([]byte)) != string(expectedSecret) {
		t.Error("Returned secret does not match expected secret")
	}
}

func TestJwtSecretKeyFunc_InvalidRS256(t *testing.T) {
	// Create a token with RS256
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{})

	_, err := jwtSecretKeyFunc(token)
	if err == nil {
		t.Fatal("Expected error for RS256 token, but got none")
	}

	expectedError := "unexpected signing method: only HS256 is allowed"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

func TestJwtSecretKeyFunc_InvalidHS384(t *testing.T) {
	// Create a token with HS384 (different HMAC algorithm)
	token := jwt.NewWithClaims(jwt.SigningMethodHS384, jwt.MapClaims{})

	_, err := jwtSecretKeyFunc(token)
	if err == nil {
		t.Fatal("Expected error for HS384 token, but got none")
	}

	expectedError := "unexpected signing method: only HS256 is allowed"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

func TestJwtSecretKeyFunc_InvalidHS512(t *testing.T) {
	// Create a token with HS512 (different HMAC algorithm)
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{})

	_, err := jwtSecretKeyFunc(token)
	if err == nil {
		t.Fatal("Expected error for HS512 token, but got none")
	}

	expectedError := "unexpected signing method: only HS256 is allowed"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

func TestJwtSecretKeyFunc_InvalidNone(t *testing.T) {
	// Create a token with 'none' algorithm
	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{})

	_, err := jwtSecretKeyFunc(token)
	if err == nil {
		t.Fatal("Expected error for 'none' algorithm token, but got none")
	}

	expectedError := "unexpected signing method: only HS256 is allowed"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// Test that GenerateJWT includes iat and nbf claims
func TestGenerateJWT_IncludesIatAndNbfClaims(t *testing.T) {
	userID := "test-user-123"
	beforeGeneration := time.Now().Add(-time.Second) // Allow 1 second buffer

	token, err := GenerateJWT(userID)
	if err != nil {
		t.Fatalf("Failed to generate JWT: %v", err)
	}

	afterGeneration := time.Now().Add(time.Second) // Allow 1 second buffer

	// Parse the token to check claims
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return []byte(GetSecretKeyFromEnv()), nil
	})
	if err != nil {
		t.Fatalf("Failed to parse generated token: %v", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("Failed to parse claims")
	}

	// Check iat claim exists and is reasonable
	iatFloat, ok := claims["iat"].(float64)
	if !ok {
		t.Fatal("iat claim not found or not a number")
	}
	iat := time.Unix(int64(iatFloat), 0)
	if iat.Before(beforeGeneration) || iat.After(afterGeneration) {
		t.Errorf("iat claim %v is not within expected range [%v, %v]", iat, beforeGeneration, afterGeneration)
	}

	// Check nbf claim exists and is reasonable
	nbfFloat, ok := claims["nbf"].(float64)
	if !ok {
		t.Fatal("nbf claim not found or not a number")
	}
	nbf := time.Unix(int64(nbfFloat), 0)
	if nbf.Before(beforeGeneration) || nbf.After(afterGeneration) {
		t.Errorf("nbf claim %v is not within expected range [%v, %v]", nbf, beforeGeneration, afterGeneration)
	}

	// Check exp claim still exists
	_, ok = claims["exp"].(float64)
	if !ok {
		t.Fatal("exp claim not found or not a number")
	}
}

// Test VerifyJWT rejects tokens with missing iat claim
func TestVerifyJWT_MissingIatClaim(t *testing.T) {
	// Create a token without iat claim
	claims := jwt.MapClaims{
		"user_id": "test-user-123",
		"nbf":     time.Now().Unix(),
		"exp":     time.Now().Add(time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(GetSecretKeyFromEnv()))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// Verify should fail
	_, _, err = VerifyJWT(tokenString)
	if err == nil {
		t.Fatal("Expected error for token missing iat claim, but got none")
	}

	expectedError := "iat (issued at) not found in token"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// Test VerifyJWT rejects tokens with missing nbf claim
func TestVerifyJWT_MissingNbfClaim(t *testing.T) {
	// Create a token without nbf claim
	claims := jwt.MapClaims{
		"user_id": "test-user-123",
		"iat":     time.Now().Unix(),
		"exp":     time.Now().Add(time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(GetSecretKeyFromEnv()))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// Verify should fail
	_, _, err = VerifyJWT(tokenString)
	if err == nil {
		t.Fatal("Expected error for token missing nbf claim, but got none")
	}

	expectedError := "nbf (not before) not found in token"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// Test VerifyJWT rejects tokens with iat in the future (replay attack prevention)
func TestVerifyJWT_FutureIatClaim(t *testing.T) {
	// Create a token with iat in the future
	futureTime := time.Now().Add(time.Hour)
	claims := jwt.MapClaims{
		"user_id": "test-user-123",
		"iat":     futureTime.Unix(),
		"nbf":     time.Now().Unix(),
		"exp":     time.Now().Add(2 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(GetSecretKeyFromEnv()))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// Verify should fail
	_, _, err = VerifyJWT(tokenString)
	if err == nil {
		t.Fatal("Expected error for token with future iat claim, but got none")
	}

	expectedError := "token used before issued"
	if err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// Test VerifyJWT rejects tokens used before nbf time (premature usage prevention)
func TestVerifyJWT_PrematureNbfClaim(t *testing.T) {
	// Create a token with nbf in the future
	futureTime := time.Now().Add(time.Hour)
	claims := jwt.MapClaims{
		"user_id": "test-user-123",
		"iat":     time.Now().Unix(),
		"nbf":     futureTime.Unix(),
		"exp":     time.Now().Add(2 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(GetSecretKeyFromEnv()))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// Verify should fail
	_, _, err = VerifyJWT(tokenString)
	if err == nil {
		t.Fatal("Expected error for token used before nbf time, but got none")
	}

	// The JWT library may catch this before our validation, so check for either error
	if !strings.Contains(err.Error(), "token used before valid") && !strings.Contains(err.Error(), "token is not valid yet") {
		t.Errorf("Expected nbf validation error, got '%s'", err.Error())
	}
}

// Test VerifyJWT rejects expired tokens with explicit error message
func TestVerifyJWT_ExpiredToken(t *testing.T) {
	// Create an expired token
	pastTime := time.Now().Add(-time.Hour)
	claims := jwt.MapClaims{
		"user_id": "test-user-123",
		"iat":     pastTime.Unix(),
		"nbf":     pastTime.Unix(),
		"exp":     pastTime.Add(30 * time.Minute).Unix(), // Expired 30 minutes ago
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(GetSecretKeyFromEnv()))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// Verify should fail
	_, _, err = VerifyJWT(tokenString)
	if err == nil {
		t.Fatal("Expected error for expired token, but got none")
	}

	// The JWT library may catch this before our validation, so check for either error
	if !strings.Contains(err.Error(), "token expired") && !strings.Contains(err.Error(), "token is expired") {
		t.Errorf("Expected expiration validation error, got '%s'", err.Error())
	}
}

// Test comprehensive token replay attack scenario
func TestVerifyJWT_TokenReplayAttackPrevention(t *testing.T) {
	// Simulate an attacker trying to replay a token with manipulated iat
	userID := "test-user-123"

	// Generate a legitimate token
	legitimateToken, err := GenerateJWT(userID)
	if err != nil {
		t.Fatalf("Failed to generate legitimate JWT: %v", err)
	}

	// Parse the legitimate token to get its claims
	parsedToken, err := jwt.Parse(legitimateToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(GetSecretKeyFromEnv()), nil
	})
	if err != nil {
		t.Fatalf("Failed to parse legitimate token: %v", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("Failed to parse claims from legitimate token")
	}

	// Create a malicious token with iat set to future (replay attack)
	maliciousClaims := jwt.MapClaims{
		"user_id": claims["user_id"],
		"iat":     time.Now().Add(time.Hour).Unix(), // Future iat
		"nbf":     claims["nbf"],
		"exp":     claims["exp"],
	}

	maliciousToken := jwt.NewWithClaims(jwt.SigningMethodHS256, maliciousClaims)
	maliciousTokenString, err := maliciousToken.SignedString([]byte(GetSecretKeyFromEnv()))
	if err != nil {
		t.Fatalf("Failed to sign malicious token: %v", err)
	}

	// Verify the legitimate token should work
	_, _, err = VerifyJWT(legitimateToken)
	if err != nil {
		t.Fatalf("Legitimate token should be valid: %v", err)
	}

	// Verify the malicious token should be rejected
	_, _, err = VerifyJWT(maliciousTokenString)
	if err == nil {
		t.Fatal("Malicious token with future iat should be rejected")
	}

	if !strings.Contains(err.Error(), "token used before issued") {
		t.Errorf("Expected replay attack error, got: %v", err)
	}
}

// Test comprehensive premature token usage scenario
func TestVerifyJWT_PrematureTokenUsagePrevention(t *testing.T) {
	// Create a token that's valid but not yet active (nbf in future)
	userID := "test-user-123"
	now := time.Now()

	claims := jwt.MapClaims{
		"user_id": userID,
		"iat":     now.Unix(),
		"nbf":     now.Add(30 * time.Minute).Unix(), // Valid in 30 minutes
		"exp":     now.Add(2 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(GetSecretKeyFromEnv()))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// Token should be rejected when used prematurely
	_, _, err = VerifyJWT(tokenString)
	if err == nil {
		t.Fatal("Token used before nbf time should be rejected")
	}

	// The JWT library may catch this before our validation, so check for either error
	if !strings.Contains(err.Error(), "token used before valid") && !strings.Contains(err.Error(), "token is not valid yet") {
		t.Errorf("Expected premature usage error, got: %v", err)
	}
}

// Test that our custom validation logic works by bypassing JWT library's automatic validation
func TestVerifyJWT_CustomValidationLogic(t *testing.T) {
	// Test our custom iat validation specifically
	userID := "test-user-123"
	futureTime := time.Now().Add(time.Hour)

	// Create a token with future iat but valid exp and nbf
	claims := jwt.MapClaims{
		"user_id": userID,
		"iat":     futureTime.Unix(), // Future iat - should trigger our custom validation
		"nbf":     time.Now().Unix(),
		"exp":     time.Now().Add(2 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(GetSecretKeyFromEnv()))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// This should specifically trigger our iat validation
	_, _, err = VerifyJWT(tokenString)
	if err == nil {
		t.Fatal("Expected error for future iat claim, but got none")
	}

	// This should be caught by our custom validation
	if !strings.Contains(err.Error(), "token used before issued") {
		t.Errorf("Expected our custom iat validation error, got: %v", err)
	}
}

// Test edge case: token with all time claims in the past but still valid
func TestVerifyJWT_ValidPastToken(t *testing.T) {
	userID := "test-user-123"
	pastTime := time.Now().Add(-time.Hour)

	// Create a token that was issued in the past but is still valid
	claims := jwt.MapClaims{
		"user_id": userID,
		"iat":     pastTime.Unix(),                  // Issued 1 hour ago
		"nbf":     pastTime.Unix(),                  // Valid since 1 hour ago
		"exp":     time.Now().Add(time.Hour).Unix(), // Expires in 1 hour
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(GetSecretKeyFromEnv()))
	if err != nil {
		t.Fatalf("Failed to sign token: %v", err)
	}

	// This should be valid
	extractedUserID, expTime, err := VerifyJWT(tokenString)
	if err != nil {
		t.Fatalf("Valid past token should be accepted: %v", err)
	}

	if extractedUserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, extractedUserID)
	}

	if expTime.Before(time.Now()) {
		t.Error("Token expiration time should be in the future")
	}
}

func TestJWTKeyRotation(t *testing.T) {
	userID := "test-user-123"

	originalToken, err := GenerateJWT(userID)
	if err != nil {
		t.Fatalf("Failed to generate JWT with original key: %v", err)
	}

	originalUserID, _, err := VerifyJWT(originalToken)
	if err != nil {
		t.Fatalf("Failed to verify JWT with original key: %v", err)
	}
	if originalUserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, originalUserID)
	}

	newKey := make([]byte, 32)
	for i := range newKey {
		newKey[i] = byte(i + 100)
	}

	RotateJWTKey(newKey)

	newToken, err := GenerateJWT(userID)
	if err != nil {
		t.Fatalf("Failed to generate JWT with new key: %v", err)
	}

	newUserID, _, err := VerifyJWT(newToken)
	if err != nil {
		t.Fatalf("Failed to verify JWT with new key: %v", err)
	}
	if newUserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, newUserID)
	}

	oldUserID, _, err := VerifyJWT(originalToken)
	if err != nil {
		t.Fatalf("Failed to verify old JWT after key rotation: %v", err)
	}
	if oldUserID != userID {
		t.Errorf("Expected user ID %s, got %s", userID, oldUserID)
	}

	if originalToken == newToken {
		t.Error("New token should be different from original token after key rotation")
	}
}
