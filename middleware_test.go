package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"bus.zcauldron.com/pkg/middleware"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// Mock login handler that doesn't require database
func mockLoginHandler(c *gin.Context) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	
	// Get IP using same logic as middleware
	ip := c.ClientIP()
	if gin.Mode() == gin.TestMode {
		if forwardedIP := c.GetHeader("X-Forwarded-For"); forwardedIP != "" {
			ip = forwardedIP
		}
	}
	
	// Simulate failed login for any credentials
	middleware.RecordFailedLogin(ip)
	c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
}

func setupMockRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	
	// Trust all proxies for testing to allow X-Forwarded-For header
	router.SetTrustedProxies([]string{"0.0.0.0/0"})
	
	router.POST("/login", middleware.BruteForceProtection(), mockLoginHandler)
	
	return router
}

func TestBruteForceProtectionIsolated(t *testing.T) {
	router := setupMockRouter()
	
	t.Run("Protection Activates After 5 Failed Attempts", func(t *testing.T) {
		middleware.ClearLoginAttempts()
		
		loginData := map[string]interface{}{
			"username": "testuser",
			"password": "wrongpassword",
		}
		
		sourceIP := "192.168.1.100"
		var responses []int
		
		// Make 8 failed login attempts
		for i := 0; i < 8; i++ {
			jsonData, _ := json.Marshal(loginData)
			req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonData))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", sourceIP)
			
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			responses = append(responses, w.Code)
			
			t.Logf("Attempt %d: Status %d", i+1, w.Code)
			time.Sleep(50 * time.Millisecond)
		}
		
		// First 5 attempts should reach the handler (401)
		// Attempts 6+ should be blocked by middleware (429)
		unauthorizedCount := 0
		blockedCount := 0
		
		for i, code := range responses {
			if code == http.StatusUnauthorized {
				unauthorizedCount++
			} else if code == http.StatusTooManyRequests {
				blockedCount++
			}
			
			if i >= 5 {
				assert.Equal(t, http.StatusTooManyRequests, code, 
					"Attempt %d should be blocked", i+1)
			}
		}
		
		assert.Equal(t, 5, unauthorizedCount, "Should have 5 unauthorized responses")
		assert.Equal(t, 3, blockedCount, "Should have 3 blocked responses")
		
		t.Logf("Unauthorized: %d, Blocked: %d", unauthorizedCount, blockedCount)
	})
	
	t.Run("Multiple IPs Tracked Independently", func(t *testing.T) {
		middleware.ClearLoginAttempts()
		
		loginData := map[string]interface{}{
			"username": "testuser",
			"password": "wrongpassword",
		}
		
		ips := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}
		
	for ipIndex, ip := range ips {
		t.Logf("Testing IP: %s", ip)			
			// Each IP should be able to make 5 attempts before lockout
			for i := 0; i < 7; i++ {
				jsonData, _ := json.Marshal(loginData)
				req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonData))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Forwarded-For", ip)
				
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			
			t.Logf("  Attempt %d: Status %d", i+1, w.Code)				
				if i < 5 {
					assert.Equal(t, http.StatusUnauthorized, w.Code,
						"IP %s attempt %d should reach handler", ip, i+1)
				} else {
					assert.Equal(t, http.StatusTooManyRequests, w.Code,
						"IP %s attempt %d should be blocked", ip, i+1)
				}
				
				time.Sleep(50 * time.Millisecond)
			}
			
		// Verify this IP is locked but others aren't
		if ipIndex < len(ips)-1 {
			nextIP := ips[ipIndex+1]
			jsonData, _ := json.Marshal(loginData)
			req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonData))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", nextIP)
			
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			
			assert.Equal(t, http.StatusUnauthorized, w.Code,
				"Next IP %s should not be affected by previous IP lockout", nextIP)
			
			// Clear the attempt created by this verification request
			// so it doesn't affect the next IP's test
			middleware.ClearLoginAttemptsForIP(nextIP)
		}		}
	})
	
	t.Run("Lockout Response Contains Retry Information", func(t *testing.T) {
		middleware.ClearLoginAttempts()
		
		loginData := map[string]interface{}{
			"username": "admin",
			"password": "password",
		}
		
		sourceIP := "172.16.0.1"
		
		// Trigger lockout with 6 attempts
		for i := 0; i < 6; i++ {
			jsonData, _ := json.Marshal(loginData)
			req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonData))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", sourceIP)
			
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			
			if i == 5 { // Check the lockout response
				assert.Equal(t, http.StatusTooManyRequests, w.Code)
				
				var response map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &response)
				assert.NoError(t, err)
				
				assert.Contains(t, response, "error")
				assert.Contains(t, response, "retry_after_seconds")
				
				retryAfter, ok := response["retry_after_seconds"].(float64)
				assert.True(t, ok, "retry_after_seconds should be a number")
				assert.Greater(t, retryAfter, 0.0, "retry_after_seconds should be positive")
				
				t.Logf("Lockout response: %s", w.Body.String())
				t.Logf("Retry after: %.0f seconds", retryAfter)
			}
			
			time.Sleep(50 * time.Millisecond)
		}
	})
}

func TestBruteForceAttackPatterns(t *testing.T) {
	router := setupMockRouter()
	
	t.Run("Credential Stuffing Attack", func(t *testing.T) {
		middleware.ClearLoginAttempts()
		
		// Common username/password combinations
		credentials := []map[string]string{
			{"username": "admin", "password": "admin"},
			{"username": "admin", "password": "password"},
			{"username": "admin", "password": "123456"},
			{"username": "root", "password": "root"},
			{"username": "user", "password": "user"},
			{"username": "test", "password": "test"},
			{"username": "guest", "password": "guest"},
		}
		
		sourceIP := "203.0.113.1"
		
		for i, cred := range credentials {
			jsonData, _ := json.Marshal(cred)
			req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonData))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", sourceIP)
			
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			
			t.Logf("Credential stuffing %d (%s:%s): Status %d", 
				i+1, cred["username"], cred["password"], w.Code)
			
			if i >= 5 {
				assert.Equal(t, http.StatusTooManyRequests, w.Code,
					"Should be blocked during credential stuffing")
			}
			
			time.Sleep(100 * time.Millisecond)
		}
	})
	
	t.Run("Password Spraying Attack", func(t *testing.T) {
		middleware.ClearLoginAttempts()
		
		// Try same password against multiple usernames
		usernames := []string{"admin", "administrator", "root", "user", "test", "guest"}
		password := "password123"
		sourceIP := "198.51.100.1"
		
		for i, username := range usernames {
			loginData := map[string]interface{}{
				"username": username,
				"password": password,
			}
			
			jsonData, _ := json.Marshal(loginData)
			req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonData))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", sourceIP)
			
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			
			t.Logf("Password spray %d (%s:%s): Status %d", 
				i+1, username, password, w.Code)
			
			if i >= 5 {
				assert.Equal(t, http.StatusTooManyRequests, w.Code,
					"Should be blocked during password spraying")
			}
			
			time.Sleep(100 * time.Millisecond)
		}
	})
}

func TestBruteForcePerformance(t *testing.T) {
	router := setupMockRouter()
	
	t.Run("High Volume Attack Performance", func(t *testing.T) {
		middleware.ClearLoginAttempts()
		
		loginData := map[string]interface{}{
			"username": "testuser",
			"password": "wrongpassword",
		}
		
		sourceIP := "10.1.1.1"
		attackStart := time.Now()
		
		// Simulate 100 rapid requests
		for i := 0; i < 100; i++ {
			jsonData, _ := json.Marshal(loginData)
			req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonData))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", sourceIP)
			
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			
			// After 5 attempts, all should be blocked quickly
			if i >= 5 {
				assert.Equal(t, http.StatusTooManyRequests, w.Code)
			}
		}
		
		attackDuration := time.Since(attackStart)
		t.Logf("100 requests processed in %v", attackDuration)
		
		// Should handle requests quickly even under attack
		assert.Less(t, attackDuration, 5*time.Second, 
			"Should handle high volume attacks efficiently")
	})
}

func BenchmarkBruteForceProtection(b *testing.B) {
	router := setupMockRouter()
	middleware.ClearLoginAttempts()
	
	loginData := map[string]interface{}{
		"username": "testuser",
		"password": "wrongpassword",
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		jsonData, _ := json.Marshal(loginData)
		req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(jsonData))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "192.168.1.1")
		
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
	}
}

// Mock signup handler that doesn't require database
func mockSignUpHandler(c *gin.Context) {
	var body struct {
		Username        string `json:"username"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirmPassword"`
		Email           string `json:"email"`
		TermsAccepted   bool   `json:"termsAccepted"`
	}
	
	if err := c.BindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	
	// Get IP using same logic as middleware
	ip := c.ClientIP()
	if gin.Mode() == gin.TestMode {
		if forwardedIP := c.GetHeader("X-Forwarded-For"); forwardedIP != "" {
			ip = forwardedIP
		}
	}
	
	// Simulate failed signup for any credentials (e.g., username already exists)
	middleware.RecordFailedLogin(ip)
	c.JSON(http.StatusConflict, gin.H{"error": "Username already exists"})
}

func setupMockSignUpRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	
	// Trust all proxies for testing to allow X-Forwarded-For header
	router.SetTrustedProxies([]string{"0.0.0.0/0"})
	
	router.POST("/sign-up", middleware.BruteForceProtection(), mockSignUpHandler)
	
	return router
}

func TestSignUpBruteForceProtection(t *testing.T) {
	router := setupMockSignUpRouter()
	
	t.Run("SignUp Protection Activates After 5 Failed Attempts", func(t *testing.T) {
		middleware.ClearLoginAttempts()
		
		signUpData := map[string]interface{}{
			"username":        "testuser",
			"password":        "Password123!",
			"confirmPassword": "Password123!",
			"email":           "test@example.com",
			"termsAccepted":   true,
		}
		
		sourceIP := "192.168.2.100"
		var responses []int
		
		// Make 8 failed signup attempts
		for i := 0; i < 8; i++ {
			jsonData, _ := json.Marshal(signUpData)
			req, _ := http.NewRequest("POST", "/sign-up", bytes.NewBuffer(jsonData))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", sourceIP)
			
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			responses = append(responses, w.Code)
			
			t.Logf("SignUp Attempt %d: Status %d", i+1, w.Code)
			time.Sleep(50 * time.Millisecond)
		}
		
		// First 5 attempts should reach the handler (409 - conflict)
		// Attempts 6+ should be blocked by middleware (429)
		conflictCount := 0
		blockedCount := 0
		
		for i, code := range responses {
			if code == http.StatusConflict {
				conflictCount++
			} else if code == http.StatusTooManyRequests {
				blockedCount++
			}
			
			if i >= 5 {
				assert.Equal(t, http.StatusTooManyRequests, code, 
					"SignUp attempt %d should be blocked", i+1)
			}
		}
		
		assert.Equal(t, 5, conflictCount, "Should have 5 conflict responses")
		assert.Equal(t, 3, blockedCount, "Should have 3 blocked responses")
		
		t.Logf("Conflicts: %d, Blocked: %d", conflictCount, blockedCount)
	})
	
	t.Run("SignUp Multiple IPs Tracked Independently", func(t *testing.T) {
		middleware.ClearLoginAttempts()
		
		signUpData := map[string]interface{}{
			"username":        "newuser",
			"password":        "Password123!",
			"confirmPassword": "Password123!",
			"email":           "new@example.com",
			"termsAccepted":   true,
		}
		
		ips := []string{"10.0.1.1", "10.0.1.2", "10.0.1.3"}
		
		for ipIndex, ip := range ips {
			t.Logf("Testing SignUp IP: %s", ip)
			// Each IP should be able to make 5 attempts before lockout
			for i := 0; i < 7; i++ {
				jsonData, _ := json.Marshal(signUpData)
				req, _ := http.NewRequest("POST", "/sign-up", bytes.NewBuffer(jsonData))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Forwarded-For", ip)
				
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				
				t.Logf("  SignUp Attempt %d: Status %d", i+1, w.Code)
				if i < 5 {
					assert.Equal(t, http.StatusConflict, w.Code,
						"IP %s signup attempt %d should reach handler", ip, i+1)
				} else {
					assert.Equal(t, http.StatusTooManyRequests, w.Code,
						"IP %s signup attempt %d should be blocked", ip, i+1)
				}
				
				time.Sleep(50 * time.Millisecond)
			}
			
			// Verify this IP is locked but others aren't
			if ipIndex < len(ips)-1 {
				nextIP := ips[ipIndex+1]
				jsonData, _ := json.Marshal(signUpData)
				req, _ := http.NewRequest("POST", "/sign-up", bytes.NewBuffer(jsonData))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("X-Forwarded-For", nextIP)
				
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)
				
				assert.Equal(t, http.StatusConflict, w.Code,
					"Next IP %s should not be affected by previous IP lockout", nextIP)
				
				// Clear the attempt created by this verification request
				middleware.ClearLoginAttemptsForIP(nextIP)
			}
		}
	})
}

func TestSignUpBruteForceAttackPatterns(t *testing.T) {
	router := setupMockSignUpRouter()
	
	t.Run("SignUp Account Creation Spam Attack", func(t *testing.T) {
		middleware.ClearLoginAttempts()
		
		// Attempt to create multiple accounts with similar usernames
		usernames := []string{"admin", "administrator", "root", "user", "test", "guest", "support"}
		sourceIP := "203.0.113.2"
		
		for i, username := range usernames {
			signUpData := map[string]interface{}{
				"username":        username,
				"password":        "Password123!",
				"confirmPassword": "Password123!",
				"email":           username + "@example.com",
				"termsAccepted":   true,
			}
			
			jsonData, _ := json.Marshal(signUpData)
			req, _ := http.NewRequest("POST", "/sign-up", bytes.NewBuffer(jsonData))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", sourceIP)
			
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			
			t.Logf("Account spam %d (%s): Status %d", 
				i+1, username, w.Code)
			
			if i >= 5 {
				assert.Equal(t, http.StatusTooManyRequests, w.Code,
					"Should be blocked during account creation spam")
			}
			
			time.Sleep(100 * time.Millisecond)
		}
	})
	
	t.Run("SignUp Email Enumeration Attack", func(t *testing.T) {
		middleware.ClearLoginAttempts()
		
		// Try to enumerate valid emails by attempting signups
		emails := []string{
			"admin@company.com", 
			"support@company.com", 
			"info@company.com", 
			"sales@company.com", 
			"contact@company.com", 
			"help@company.com",
		}
		sourceIP := "198.51.100.2"
		
		for i, email := range emails {
			signUpData := map[string]interface{}{
				"username":        "user" + string(rune(i+65)), // userA, userB, etc.
				"password":        "Password123!",
				"confirmPassword": "Password123!",
				"email":           email,
				"termsAccepted":   true,
			}
			
			jsonData, _ := json.Marshal(signUpData)
			req, _ := http.NewRequest("POST", "/sign-up", bytes.NewBuffer(jsonData))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", sourceIP)
			
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			
			t.Logf("Email enumeration %d (%s): Status %d", 
				i+1, email, w.Code)
			
			if i >= 5 {
				assert.Equal(t, http.StatusTooManyRequests, w.Code,
					"Should be blocked during email enumeration")
			}
			
			time.Sleep(100 * time.Millisecond)
		}
	})
}

func TestSignUpBruteForcePerformance(t *testing.T) {
	router := setupMockSignUpRouter()
	
	t.Run("SignUp High Volume Attack Performance", func(t *testing.T) {
		middleware.ClearLoginAttempts()
		
		signUpData := map[string]interface{}{
			"username":        "spammer",
			"password":        "Password123!",
			"confirmPassword": "Password123!",
			"email":           "spam@example.com",
			"termsAccepted":   true,
		}
		
		sourceIP := "10.2.2.2"
		attackStart := time.Now()
		
		// Simulate 50 rapid signup requests
		for i := 0; i < 50; i++ {
			jsonData, _ := json.Marshal(signUpData)
			req, _ := http.NewRequest("POST", "/sign-up", bytes.NewBuffer(jsonData))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Forwarded-For", sourceIP)
			
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			
			// After 5 attempts, all should be blocked quickly
			if i >= 5 {
				assert.Equal(t, http.StatusTooManyRequests, w.Code)
			}
		}
		
		attackDuration := time.Since(attackStart)
		t.Logf("50 signup requests processed in %v", attackDuration)
		
		// Should handle requests quickly even under attack
		assert.Less(t, attackDuration, 3*time.Second, 
			"Should handle high volume signup attacks efficiently")
	})
}