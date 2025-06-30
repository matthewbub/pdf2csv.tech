package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"bus.zcauldron.com/pkg/utils"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func TestMain(m *testing.M) {
	// Set test environment
	if err := utils.SetTestEnvironment(); err != nil {
		panic(err)
	}

	// Run test migrations to set up database tables
	if err := utils.RunMigrationsTest(); err != nil {
		panic(err)
	}

	gin.SetMode(gin.TestMode)
	exitCode := m.Run()
	os.Exit(exitCode)
}

func setupTestRouter() *gin.Engine {
	router := gin.New()
	router.Use(JWTAuthMiddleware())
	router.GET("/protected", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})
	return router
}

func TestJWTAuthMiddleware_ValidHS256Token(t *testing.T) {
	router := setupTestRouter()

	// Generate a valid HS256 token
	token, err := utils.GenerateJWT("test-user-123")
	if err != nil {
		t.Fatalf("Failed to generate JWT: %v", err)
	}

	// Create request with valid token
	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "jwt",
		Value: token,
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestJWTAuthMiddleware_MissingToken(t *testing.T) {
	router := setupTestRouter()

	// Create request without token
	req := httptest.NewRequest("GET", "/protected", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestJWTAuthMiddleware_InvalidAlgorithm_RS256(t *testing.T) {
	router := setupTestRouter()

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

	// Create request with RS256 token
	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "jwt",
		Value: tokenString,
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should be rejected
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for RS256 token, got %d", w.Code)
	}
}

func TestJWTAuthMiddleware_InvalidAlgorithm_HS384(t *testing.T) {
	router := setupTestRouter()

	// Create a token with HS384 algorithm
	claims := jwt.MapClaims{
		"user_id": "test-user-123",
		"exp":     time.Now().Add(time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS384, claims)
	tokenString, err := token.SignedString([]byte(utils.GetSecretKeyFromEnv()))
	if err != nil {
		t.Fatalf("Failed to sign HS384 token: %v", err)
	}

	// Create request with HS384 token
	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "jwt",
		Value: tokenString,
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should be rejected
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for HS384 token, got %d", w.Code)
	}
}

func TestJWTAuthMiddleware_InvalidAlgorithm_HS512(t *testing.T) {
	router := setupTestRouter()

	// Create a token with HS512 algorithm
	claims := jwt.MapClaims{
		"user_id": "test-user-123",
		"exp":     time.Now().Add(time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	tokenString, err := token.SignedString([]byte(utils.GetSecretKeyFromEnv()))
	if err != nil {
		t.Fatalf("Failed to sign HS512 token: %v", err)
	}

	// Create request with HS512 token
	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "jwt",
		Value: tokenString,
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should be rejected
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for HS512 token, got %d", w.Code)
	}
}

func TestJWTAuthMiddleware_InvalidAlgorithm_None(t *testing.T) {
	router := setupTestRouter()

	// Create a token with 'none' algorithm
	claims := jwt.MapClaims{
		"user_id": "test-user-123",
		"exp":     time.Now().Add(time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("Failed to sign 'none' token: %v", err)
	}

	// Create request with 'none' algorithm token
	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "jwt",
		Value: tokenString,
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should be rejected
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for 'none' algorithm token, got %d", w.Code)
	}
}

func TestJWTAuthMiddleware_ExpiredToken(t *testing.T) {
	router := setupTestRouter()

	// Create an expired token
	claims := jwt.MapClaims{
		"user_id": "test-user-123",
		"exp":     time.Now().Add(-time.Hour).Unix(), // Expired 1 hour ago
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(utils.GetSecretKeyFromEnv()))
	if err != nil {
		t.Fatalf("Failed to sign expired token: %v", err)
	}

	// Create request with expired token
	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "jwt",
		Value: tokenString,
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should be rejected
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for expired token, got %d", w.Code)
	}
}

func TestJWTAuthMiddleware_MalformedToken(t *testing.T) {
	router := setupTestRouter()

	// Create request with malformed token
	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "jwt",
		Value: "invalid.token.here",
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should be rejected
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for malformed token, got %d", w.Code)
	}
}

// Test algorithm confusion attack scenario
func TestJWTAuthMiddleware_AlgorithmConfusionAttack(t *testing.T) {
	router := setupTestRouter()

	// This test simulates an algorithm confusion attack where an attacker
	// tries to use the HMAC secret as an RSA public key

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	// Create a token signed with RSA private key but claiming to be HS256
	// This is a common attack vector
	claims := jwt.MapClaims{
		"user_id": "attacker",
		"exp":     time.Now().Add(time.Hour).Unix(),
	}

	// Sign with RS256 but attacker hopes server will verify with HS256
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatalf("Failed to sign attack token: %v", err)
	}

	// Create request with attack token
	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "jwt",
		Value: tokenString,
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Our fix should reject this attack
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Algorithm confusion attack was not blocked! Expected status 401, got %d", w.Code)
		t.Error("SECURITY VULNERABILITY: Algorithm confusion attack succeeded")
	}
}
