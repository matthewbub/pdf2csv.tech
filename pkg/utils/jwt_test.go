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