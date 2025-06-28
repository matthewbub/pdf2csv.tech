package test

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func RegisterUserAtSignup(router *gin.Engine, t *testing.T) {
	log.Println("Getting next available test user...")
	username, email, err := GetNextUser()
	if err != nil {
		t.Fatalf("Failed to get next user: %v", err)
	}
	if username == "" || email == "" {
		t.Fatalf("Failed to get next user")
	}
	log.Printf("Using test user: %s (%s)", username, email)
	
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

	log.Println("Sending POST request to /api/v1/public/sign-up")
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/api/v1/public/sign-up", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(w, req)

	log.Printf("Response status: %d", w.Code)
	if w.Code != http.StatusOK {
		log.Printf("Response body: %s", w.Body.String())
		t.Logf("Response body: %s", w.Body.String())
	} else {
		log.Println("Sign-up request successful")
	}

	assert.Equal(t, http.StatusOK, w.Code)
}
