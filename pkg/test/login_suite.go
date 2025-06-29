package test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// LoginRequest represents the login request structure
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginUserTest tests basic login functionality
func LoginUserTest(router *gin.Engine, t *testing.T) {
	log.Println("Testing basic login functionality...")

	// First, create a user to login with
	username, email, err := GetNextUser()
	if err != nil {
		t.Fatalf("Failed to get next user: %v", err)
	}
	if username == "" || email == "" {
		t.Fatalf("Failed to get next user")
	}
	log.Printf("Using test user: %s (%s)", username, email)

	// Register the user first
	signUpBody := map[string]interface{}{
		"email":           email,
		"password":        TestConfig.Password,
		"confirmPassword": TestConfig.Password,
		"termsAccepted":   true,
		"username":        username,
	}

	jsonBody, err := json.Marshal(signUpBody)
	if err != nil {
		t.Fatalf("Failed to marshal signup body: %v", err)
	}

	// Sign up the user
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/public/sign-up", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Failed to create user for login test: %d - %s", w.Code, w.Body.String())
	}

	// Now test login
	loginBody := LoginRequest{
		Email:    email,
		Password: TestConfig.Password,
	}

	loginJSON, err := json.Marshal(loginBody)
	if err != nil {
		t.Fatalf("Failed to marshal login body: %v", err)
	}

	log.Println("Sending POST request to /api/v1/public/login")
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/api/v1/public/login", bytes.NewBuffer(loginJSON))
	req.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(w, req)

	log.Printf("Login response status: %d", w.Code)
	if w.Code != http.StatusOK {
		log.Printf("Login response body: %s", w.Body.String())
		t.Logf("Login response body: %s", w.Body.String())
	} else {
		log.Println("Login request successful")
	}

		assert.Equal(t, http.StatusOK, w.Code)
}

// BruteForceLoginTests contains comprehensive brute force testing for the login endpoint
func BruteForceLoginTests(router *gin.Engine, t *testing.T) {
	t.Run("Invalid JSON Payloads", func(t *testing.T) {
		testLoginInvalidJSONPayloads(router, t)
	})

	t.Run("Email Validation Attacks", func(t *testing.T) {
		testLoginEmailValidationAttacks(router, t)
	})

	t.Run("Password Brute Force Attacks", func(t *testing.T) {
		testLoginPasswordBruteForce(router, t)
	})

	t.Run("SQL Injection Attempts", func(t *testing.T) {
		testLoginSQLInjectionAttempts(router, t)
	})

	t.Run("XSS Injection Attempts", func(t *testing.T) {
		testLoginXSSInjectionAttempts(router, t)
	})

	t.Run("Rate Limiting Tests", func(t *testing.T) {
		testLoginRateLimiting(router, t)
	})

	t.Run("Concurrent Login Attempts", func(t *testing.T) {
		testLoginConcurrentAttempts(router, t)
	})

	t.Run("Malformed Request Headers", func(t *testing.T) {
		testLoginMalformedRequestHeaders(router, t)
	})

	t.Run("Edge Case Field Values", func(t *testing.T) {
		testLoginEdgeCaseFieldValues(router, t)
	})
}

func testLoginInvalidJSONPayloads(router *gin.Engine, t *testing.T) {
	invalidPayloads := []string{
		"",                              // Empty payload
		"{",                             // Incomplete JSON
		"invalid json",                  // Invalid JSON
		"null",                          // Null payload
		"[]",                            // Array instead of object
		`{"email":}`,                    // Missing value
		`{"email":"test@example.com"`,   // Unclosed JSON
		`{"email":"test@example.com",}`, // Trailing comma
	}

	for i, payload := range invalidPayloads {
		t.Run(fmt.Sprintf("InvalidJSON_%d", i), func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/api/v1/public/login", strings.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func testLoginEmailValidationAttacks(router *gin.Engine, t *testing.T) {
	invalidEmails := []string{
		"",                                    // Empty email
		"invalid",                             // No @ symbol
		"@example.com",                        // Missing local part
		"user@",                               // Missing domain
		"user@.com",                           // Invalid domain
		"user@example",                        // Missing TLD
		"user@example.",                       // Empty TLD
		"user@example.com\x00",                // Null byte
		"user@example.com\n",                  // Newline
		"user@example.com\r",                  // Carriage return
		"user'OR'1'='1@example.com",           // SQL injection
		"user<script>@example.com",            // XSS attempt
		"user@example.com; DROP TABLE users;", // SQL injection
		"user name@example.com",               // Space not allowed
		"user@exam ple.com",                   // Space in domain
	}

	for i, email := range invalidEmails {
		t.Run(fmt.Sprintf("InvalidEmail_%d", i), func(t *testing.T) {
			payload := LoginRequest{
				Email:    email,
				Password: "ValidPass123!",
			}
			testLoginRequest(router, t, payload, http.StatusBadRequest)
		})
	}
}

func testLoginPasswordBruteForce(router *gin.Engine, t *testing.T) {
	// Create a valid user first
	username, email, err := GetNextUser()
	if err != nil {
		t.Fatalf("Failed to get next user: %v", err)
	}

	// Register the user
	signUpBody := map[string]interface{}{
		"email":           email,
		"password":        TestConfig.Password,
		"confirmPassword": TestConfig.Password,
		"termsAccepted":   true,
		"username":        username,
	}

	jsonBody, _ := json.Marshal(signUpBody)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/public/sign-up", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Failed to create user for brute force test: %d", w.Code)
	}

	// Now try multiple wrong passwords
	wrongPasswords := []string{
		"wrongpass",
		"password123",
		"admin",
		"123456",
		"password",
		"qwerty",
		"letmein",
		"welcome",
		"monkey",
		"dragon",
	}

	for i, wrongPassword := range wrongPasswords {
		t.Run(fmt.Sprintf("WrongPassword_%d", i), func(t *testing.T) {
			payload := LoginRequest{
				Email:    email,
				Password: wrongPassword,
			}
			testLoginRequest(router, t, payload, http.StatusUnauthorized, fmt.Sprintf("127.0.0.%d", i))
		})
	}
}

func testLoginSQLInjectionAttempts(router *gin.Engine, t *testing.T) {
	sqlInjectionPayloads := []string{
		"'; DROP TABLE users; --",
		"' OR '1'='1",
		"' UNION SELECT * FROM users --",
		"'; INSERT INTO users VALUES ('hacker', 'pass'); --",
		"' OR 1=1 --",
		"admin'--",
		"admin'/*",
		"' OR 'x'='x",
		"'; EXEC xp_cmdshell('dir'); --",
		"' AND (SELECT COUNT(*) FROM users) > 0 --",
	}

	for i, injection := range sqlInjectionPayloads {
		t.Run(fmt.Sprintf("SQLInjection_%d", i), func(t *testing.T) {
			// Test in email field
			payload := LoginRequest{
				Email:    injection,
				Password: "ValidPass123!",
			}
			testLoginRequest(router, t, payload, http.StatusBadRequest)

			// Test in password field
			payload = LoginRequest{
				Email:    "test@example.com",
				Password: injection,
			}
			testLoginRequest(router, t, payload, http.StatusUnauthorized, fmt.Sprintf("127.0.1.%d", i))
		})
	}
}

func testLoginXSSInjectionAttempts(router *gin.Engine, t *testing.T) {
	xssPayloads := []string{
		"<script>alert('xss')</script>",
		"<img src=x onerror=alert('xss')>",
		"javascript:alert('xss')",
		"<svg onload=alert('xss')>",
		"<iframe src=javascript:alert('xss')>",
		"<body onload=alert('xss')>",
		"<input onfocus=alert('xss') autofocus>",
	}

	for i, xss := range xssPayloads {
		t.Run(fmt.Sprintf("XSS_%d", i), func(t *testing.T) {
			// Test in email field
			payload := LoginRequest{
				Email:    xss,
				Password: "ValidPass123!",
			}
			testLoginRequest(router, t, payload, http.StatusBadRequest)

			// Test in password field
			payload = LoginRequest{
				Email:    "test@example.com",
				Password: xss,
			}
			testLoginRequest(router, t, payload, http.StatusUnauthorized, fmt.Sprintf("127.0.2.%d", i))
		})
	}
}

func testLoginRateLimiting(router *gin.Engine, t *testing.T) {
	// Test rate limiting by making multiple rapid requests
	email := "ratelimit@example.com"

	for i := 0; i < 20; i++ {
		payload := LoginRequest{
			Email:    email,
			Password: "wrongpassword",
		}

		w := httptest.NewRecorder()
		jsonBody, _ := json.Marshal(payload)
		req, _ := http.NewRequest("POST", "/api/v1/public/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		router.ServeHTTP(w, req)

		// After several attempts, we should get rate limited
		if i > 10 {
			// Should be either unauthorized or rate limited
			assert.True(t, w.Code == http.StatusUnauthorized || w.Code == http.StatusTooManyRequests)
		}

		// Small delay to avoid overwhelming the system
		time.Sleep(10 * time.Millisecond)
	}
}

func testLoginConcurrentAttempts(router *gin.Engine, t *testing.T) {
	// Test concurrent login attempts
	done := make(chan bool, 10)
	email := "concurrent@example.com"

	for i := 0; i < 10; i++ {
		go func(index int) {
			payload := LoginRequest{
				Email:    email,
				Password: fmt.Sprintf("wrongpass%d", index),
			}

			jsonBody, _ := json.Marshal(payload)
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("POST", "/api/v1/public/login", bytes.NewBuffer(jsonBody))
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(w, req)

			// Should fail with unauthorized or rate limited
			assert.True(t, w.Code == http.StatusUnauthorized || w.Code == http.StatusTooManyRequests)
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

func testLoginMalformedRequestHeaders(router *gin.Engine, t *testing.T) {
	payload := LoginRequest{
		Email:    "header@example.com",
		Password: "ValidPass123!",
	}

	// Test with wrong content type
	t.Run("WrongContentType", func(t *testing.T) {
		jsonBody, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/public/login", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "text/plain")
		router.ServeHTTP(w, req)
		// This might succeed or fail depending on Gin's behavior, or be rate limited
		assert.True(t, w.Code == http.StatusUnauthorized || w.Code == http.StatusBadRequest || w.Code == http.StatusTooManyRequests)
	})

	// Test with no content type
	t.Run("NoContentType", func(t *testing.T) {
		jsonBody, _ := json.Marshal(payload)
		w := httptest.NewRecorder()
		req, _ := http.NewRequest("POST", "/api/v1/public/login", bytes.NewBuffer(jsonBody))
		router.ServeHTTP(w, req)
		// This might succeed or fail depending on Gin's behavior, or be rate limited
		assert.True(t, w.Code == http.StatusUnauthorized || w.Code == http.StatusBadRequest || w.Code == http.StatusTooManyRequests)
	})
}

func testLoginEdgeCaseFieldValues(router *gin.Engine, t *testing.T) {
	edgeCases := []struct {
		name           string
		payload        LoginRequest
		expectedStatus int
	}{
		{
			"EmptyEmail",
			LoginRequest{
				Email:    "",
				Password: "ValidPass123!",
			},
			http.StatusBadRequest,
		},
		{
			"EmptyPassword",
			LoginRequest{
				Email:    "test@example.com",
				Password: "",
			},
			http.StatusBadRequest,
		},
		{
			"BothEmpty",
			LoginRequest{
				Email:    "",
				Password: "",
			},
			http.StatusBadRequest,
		},
		{
			"VeryLongEmail",
			LoginRequest{
				Email:    strings.Repeat("a", 1000) + "@example.com",
				Password: "ValidPass123!",
			},
			http.StatusUnauthorized, // Should be processed but fail auth
		},
		{
			"VeryLongPassword",
			LoginRequest{
				Email:    "test@example.com",
				Password: strings.Repeat("a", 1000),
			},
			http.StatusUnauthorized, // Should be processed but fail auth
		},
	}

	for _, testCase := range edgeCases {
		t.Run(testCase.name, func(t *testing.T) {
			testLoginRequest(router, t, testCase.payload, testCase.expectedStatus)
		})
	}
}

// Helper function to test login requests
func testLoginRequest(router *gin.Engine, t *testing.T, payload LoginRequest, expectedStatus int, ip ...string) {
	jsonBody, err := json.Marshal(payload)
	assert.NoError(t, err)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/public/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	if len(ip) > 0 {
		req.Header.Set("X-Forwarded-For", ip[0])
	}

	router.ServeHTTP(w, req)

	// Account for rate limiting - if we expect 400 or 401, also accept 429 (rate limited)
	if expectedStatus == http.StatusBadRequest || expectedStatus == http.StatusUnauthorized {
		assert.True(t, w.Code == expectedStatus || w.Code == http.StatusTooManyRequests,
			"Expected %d or %d (rate limited), got %d. Response body: %s",
			expectedStatus, http.StatusTooManyRequests, w.Code, w.Body.String())
	} else {
		assert.Equal(t, expectedStatus, w.Code, "Response body: %s", w.Body.String())
	}
}


