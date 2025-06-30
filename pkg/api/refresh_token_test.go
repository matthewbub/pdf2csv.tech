package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"bus.zcauldron.com/pkg/constants"
	"bus.zcauldron.com/pkg/middleware"
	"bus.zcauldron.com/pkg/utils"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Setup sessions
	secretKey := utils.GetSecretKeyFromEnv()
	store := cookie.NewStore(secretKey)
	router.Use(sessions.Sessions("session", store))

	// Setup routes
	publicRoutes := router.Group("/api/v1/public")
	{
		publicRoutes.POST("/sign-up", SignUpHandler)
		publicRoutes.POST("/login", LoginHandler)
		publicRoutes.POST("/refresh-token", RefreshTokenHandler)
	}

	accountRoutes := router.Group("/api/v1/account", middleware.JWTAuthMiddleware())
	{
		accountRoutes.POST("/logout", LogoutHandler)
	}

	return router
}

func TestRefreshTokenHandler_ValidToken(t *testing.T) {
	router := setupTestRouter()

	// Generate a valid refresh token
	userID := "test-user-refresh-123"
	refreshToken, err := utils.GenerateRefreshToken(userID)
	assert.NoError(t, err)

	// Create request with refresh token cookie
	req, _ := http.NewRequest("POST", "/api/v1/public/refresh-token", nil)
	req.AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: refreshToken,
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.True(t, response["ok"].(bool))
	assert.Equal(t, "Access token refreshed successfully", response["message"])

	// Check that a new JWT cookie was set
	cookies := w.Result().Cookies()
	var jwtCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "jwt" {
			jwtCookie = cookie
			break
		}
	}
	assert.NotNil(t, jwtCookie, "JWT cookie should be set")
	assert.NotEmpty(t, jwtCookie.Value, "JWT cookie should have a value")

	// Verify the new access token is valid
	extractedUserID, _, err := utils.VerifyJWT(jwtCookie.Value)
	assert.NoError(t, err)
	assert.Equal(t, userID, extractedUserID)
}

func TestRefreshTokenHandler_MissingToken(t *testing.T) {
	router := setupTestRouter()

	req, _ := http.NewRequest("POST", "/api/v1/public/refresh-token", nil)
	// No refresh token cookie

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.False(t, response["ok"].(bool))
	assert.Equal(t, "Refresh token not found", response["error"])
}

func TestRefreshTokenHandler_InvalidToken(t *testing.T) {
	router := setupTestRouter()

	req, _ := http.NewRequest("POST", "/api/v1/public/refresh-token", nil)
	req.AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: "invalid.refresh.token",
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.False(t, response["ok"].(bool))
	assert.Equal(t, "Invalid refresh token", response["error"])
}

func TestRefreshTokenHandler_AccessTokenAsRefreshToken(t *testing.T) {
	router := setupTestRouter()

	// Generate an access token (not a refresh token)
	userID := "test-user-access-as-refresh"
	accessToken, err := utils.GenerateJWT(userID)
	assert.NoError(t, err)

	req, _ := http.NewRequest("POST", "/api/v1/public/refresh-token", nil)
	req.AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: accessToken,
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)
	assert.False(t, response["ok"].(bool))
	assert.Equal(t, "Invalid refresh token", response["error"])
}

func TestLoginGeneratesTokenPair(t *testing.T) {
	router := setupTestRouter()

	// First create a user
	signupBody := map[string]interface{}{
		"username":        "testuser_tokenpair",
		"email":           "tokenpair@test.com",
		"password":        "TestPassword123!",
		"confirmPassword": "TestPassword123!",
		"termsAccepted":   true,
	}

	signupJSON, _ := json.Marshal(signupBody)
	req, _ := http.NewRequest("POST", "/api/v1/public/sign-up", bytes.NewBuffer(signupJSON))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("Failed to create user for token pair test: %d", w.Code)
	}

	// Clear cookies from signup
	w = httptest.NewRecorder()

	// Now test login
	loginBody := map[string]interface{}{
		"username": "testuser_tokenpair",
		"password": "TestPassword123!",
	}

	loginJSON, _ := json.Marshal(loginBody)
	req, _ = http.NewRequest("POST", "/api/v1/public/login", bytes.NewBuffer(loginJSON))
	req.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Check that both JWT and refresh token cookies were set
	cookies := w.Result().Cookies()
	var jwtCookie, refreshCookie *http.Cookie

	for _, cookie := range cookies {
		if cookie.Name == "jwt" {
			jwtCookie = cookie
		} else if cookie.Name == "refresh_token" {
			refreshCookie = cookie
		}
	}

	assert.NotNil(t, jwtCookie, "JWT cookie should be set")
	assert.NotNil(t, refreshCookie, "Refresh token cookie should be set")
	assert.NotEmpty(t, jwtCookie.Value, "JWT cookie should have a value")
	assert.NotEmpty(t, refreshCookie.Value, "Refresh token cookie should have a value")

	// Verify both tokens are valid and for the same user
	jwtUserID, _, err := utils.VerifyJWT(jwtCookie.Value)
	assert.NoError(t, err)

	refreshUserID, _, err := utils.VerifyRefreshToken(refreshCookie.Value)
	assert.NoError(t, err)

	assert.Equal(t, jwtUserID, refreshUserID, "Both tokens should be for the same user")

	// Verify token expiration times are different
	assert.True(t, jwtCookie.MaxAge < refreshCookie.MaxAge, "Refresh token should have longer expiration")
}

func TestLogoutClearsBothCookies(t *testing.T) {
	router := setupTestRouter()

	// Generate tokens for a user
	userID := "test-user-logout"
	accessToken, refreshToken, err := utils.GenerateTokenPair(userID)
	assert.NoError(t, err)

	// Create logout request with both cookies
	req, _ := http.NewRequest("POST", "/api/v1/account/logout", nil)
	req.AddCookie(&http.Cookie{Name: "jwt", Value: accessToken})
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Check that both cookies are cleared (set to empty with negative MaxAge)
	cookies := w.Result().Cookies()
	var jwtCookie, refreshCookie *http.Cookie

	for _, cookie := range cookies {
		if cookie.Name == "jwt" {
			jwtCookie = cookie
		} else if cookie.Name == "refresh_token" {
			refreshCookie = cookie
		}
	}

	assert.NotNil(t, jwtCookie, "JWT cookie should be present in response")
	assert.NotNil(t, refreshCookie, "Refresh token cookie should be present in response")
	assert.Empty(t, jwtCookie.Value, "JWT cookie should be empty")
	assert.Empty(t, refreshCookie.Value, "Refresh token cookie should be empty")
	assert.True(t, jwtCookie.MaxAge < 0, "JWT cookie should have negative MaxAge")
	assert.True(t, refreshCookie.MaxAge < 0, "Refresh token cookie should have negative MaxAge")
}

func TestTokenExpirationTimes(t *testing.T) {
	// This test verifies that access tokens have shorter expiration than refresh tokens
	userID := "test-user-expiration"
	accessToken, refreshToken, err := utils.GenerateTokenPair(userID)
	assert.NoError(t, err)

	// Verify access token expiration
	_, accessExp, err := utils.VerifyJWT(accessToken)
	assert.NoError(t, err)

	// Verify refresh token expiration
	_, refreshExp, err := utils.VerifyRefreshToken(refreshToken)
	assert.NoError(t, err)

	// Access token should expire before refresh token
	assert.True(t, accessExp.Before(refreshExp), "Access token should expire before refresh token")

	// Verify the time difference matches our configuration
	expectedAccessDuration := constants.AppConfig.AccessTokenExpiration
	expectedRefreshDuration := constants.AppConfig.RefreshTokenExpiration

	accessDuration := time.Until(accessExp)
	refreshDuration := time.Until(refreshExp)

	// Allow for some variance due to test execution time
	assert.InDelta(t, expectedAccessDuration.Seconds(), accessDuration.Seconds(), 5.0)
	assert.InDelta(t, expectedRefreshDuration.Seconds(), refreshDuration.Seconds(), 5.0)
}

func TestRefreshTokenRotation(t *testing.T) {
	router := setupTestRouter()

	// Test that using a refresh token generates a new access token
	userID := "test-user-rotation"
	originalRefreshToken, err := utils.GenerateRefreshToken(userID)
	assert.NoError(t, err)

	// Use refresh token to get new access token
	req, _ := http.NewRequest("POST", "/api/v1/public/refresh-token", nil)
	req.AddCookie(&http.Cookie{
		Name:  "refresh_token",
		Value: originalRefreshToken,
	})

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Get the new access token
	cookies := w.Result().Cookies()
	var newAccessToken string
	for _, cookie := range cookies {
		if cookie.Name == "jwt" {
			newAccessToken = cookie.Value
			break
		}
	}

	assert.NotEmpty(t, newAccessToken, "New access token should be generated")

	// Verify the new access token is valid
	extractedUserID, _, err := utils.VerifyJWT(newAccessToken)
	assert.NoError(t, err)
	assert.Equal(t, userID, extractedUserID)
}
