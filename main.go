package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"bus.zcauldron.com/pkg/api"
	"bus.zcauldron.com/pkg/constants"
	"bus.zcauldron.com/pkg/middleware"
	"bus.zcauldron.com/pkg/utils"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	_ "github.com/golang-migrate/migrate/v4/database/sqlite3"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	err := utils.ValidateEnvironment()
	logger := utils.GetLogger()

	log.Printf("Starting API version %s in %s environment", constants.AppConfig.Version, os.Getenv("ENV"))
	logger.Printf("Starting API version %s in %s environment", constants.AppConfig.Version, os.Getenv("ENV"))
	if err != nil {
		logger.Fatalf("Environment validation failed: %v", err)
	}

	if err := utils.RunMigrations(); err != nil {
		logger.Fatalf("Failed to run migrations: %v", err)
	}

	// Initialize the database connection
	db := utils.GetDB()
	if db == nil {
		logger.Fatal("Failed to initialize the database connection.")
	}

	// Start background cleanup for expired blacklisted tokens
	go func() {
		ticker := time.NewTicker(1 * time.Hour) // Run cleanup every hour
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if err := utils.CleanupExpiredBlacklistedTokens(db); err != nil {
					logger.Printf("Error cleaning up expired blacklisted tokens: %v", err)
				} else {
					logger.Println("Successfully cleaned up expired blacklisted tokens")
				}
			}
		}
	}()

	router := gin.Default()
	router.Static("/_assets/", "./routes/dist/_assets")
	router.NoRoute(func(c *gin.Context) {
		// serve the app entry point here
		c.File("./routes/dist/index.html")
	})

	router.Use(middleware.Cors)
	// session management
	secretKey := utils.GetSecretKeyFromEnv()
	store := cookie.NewStore(secretKey)
	router.Use(sessions.Sessions("session", store))
	router.Use(middleware.Recovery("Something went wrong"))

	// API routes with auth below this point
	router.GET("/api/v1/schema/:type", api.SchemaHandler)
	router.GET("/health", func(c *gin.Context) {
		// ping the pdf service
		pdfServiceURL := utils.GetPDFServiceURL()
		resp, err := http.Get(pdfServiceURL + "/health")
		if err != nil {
			logger.Printf("Failed to ping PDF service: %v", err)
			c.Status(http.StatusServiceUnavailable)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			logger.Printf("PDF service is not healthy: %v", resp.StatusCode)
			c.Status(http.StatusServiceUnavailable)
			return
		}

		c.Status(http.StatusOK)
	})

	publicRoutes := router.Group("/api/v1/public", middleware.RateLimit(5*time.Second))
	{
		publicRoutes.POST("/sign-up", api.SignUpHandler)
		publicRoutes.POST("/login", middleware.BruteForceProtection(), api.LoginHandler)
		publicRoutes.POST("/refresh-token", api.RefreshTokenHandler)
	}

	accountRoutes := router.Group("/api/v1/account", middleware.JWTAuthMiddleware())
	{
		accountRoutes.GET("/auth-check", api.AuthCheckHandler)
		accountRoutes.POST("/forgot-password", api.ForgotPasswordHandler)
		accountRoutes.POST("/security-questions", api.SecurityQuestionsHandler)
		accountRoutes.POST("/logout", api.LogoutHandler)
		accountRoutes.POST("/renew-session", api.RenewSessionHandler)
		accountRoutes.POST("/in/reset-password", api.AuthenticatedResetPasswordHandler)
		accountRoutes.POST("/profile", api.UpdateProfileHandler)
		accountRoutes.DELETE("/delete", api.DeleteAccountHandler)
		accountRoutes.GET("/pages-processed", api.GetPagesProcessed)
		accountRoutes.POST("/revoke-token", api.RevokeTokenHandler)
		accountRoutes.POST("/revoke-all-tokens", api.RevokeAllTokensHandler)
	}

	pdfRoutes := router.Group("/api/v1/pdf", middleware.JWTAuthMiddleware())
	{
		pdfRoutes.POST("/extract-text", api.ExtractPDFText)
		pdfRoutes.POST("/page-count", api.GetPDFPageCount)
		pdfRoutes.POST("/page-count-native", api.GetPDFPageCountNative)
		pdfRoutes.POST("/save", api.SaveStatement)
		pdfRoutes.POST("/pdf-to-image", api.PDFToImage)
		pdfRoutes.POST("/pdf-to-image-native", api.PDFToImageNative)
		pdfRoutes.POST("/apply-drawing", api.ApplyDrawing)
	}

	router.GET("/api/v1/transactions", middleware.JWTAuthMiddleware(), api.GetUserTransactionsHandler)

	log.Println("Server is running on port 8080")
	err = router.Run(":8080")
	if err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
