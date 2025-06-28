package main

import (
	"log"
	"os"
	"testing"

	"bus.zcauldron.com/pkg/api"
	"bus.zcauldron.com/pkg/middleware"
	"bus.zcauldron.com/pkg/test"
	"bus.zcauldron.com/pkg/utils"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
)

func TestMain(m *testing.M) {
	if err := utils.SetTestEnvironment(); err != nil {
		log.Fatalf("Failed to set test environment: %v", err)
	}

	if err := utils.RunMigrations(); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	if err := utils.RunMigrationsTest(); err != nil {
		log.Fatalf("Failed to run migrations test: %v", err)
	}

	exitCode := m.Run()
	
	if err := utils.DropTestDatabase(); err != nil {
		log.Printf("Warning: Failed to clean up test database: %v", err)
	}
	
	os.Exit(exitCode)
}

func TestSignUpEndpoint(t *testing.T) {
	router := setupTestRouter()
	t.Run("Register user at signup", func(t *testing.T) {
		test.RegisterUserAtSignup(router, t)
	})
}

// setupTestRouter creates a test instance of your router
func setupTestRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	router := gin.Default()

	// middleware
	router.Use(middleware.Cors)

	// session management
	store := cookie.NewStore([]byte(os.Getenv("SESSION_SECRET_KEY")))
	router.Use(sessions.Sessions("session", store))
	router.Use(middleware.Recovery("Something went wrong"))

	// routes
	publicRoutes := router.Group("/api/v1/public")
	{
		publicRoutes.POST("/sign-up", api.SignUpHandler)
		publicRoutes.POST("/login", middleware.BruteForceProtection(), api.LoginHandler)
	}

	return router
}
