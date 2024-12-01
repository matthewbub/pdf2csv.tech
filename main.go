package main

import (
	"log"
	"net/http"
	"time"

	"bus.zcauldron.com/pkg/api"
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
	if err != nil {
		logger.Fatalf("Environment validation failed: %v", err)
	}

	if err := utils.RunMigrations(); err != nil {
		logger.Fatalf("Failed to run migrations: %v", err)
	}

	router := gin.Default()
	router.Static("/_assets/", "./routes/dist/_assets")
	router.NoRoute(func(c *gin.Context) {
		logger.Println("No route found, serving index.html")
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
		c.Status(http.StatusOK)
	})

	publicRoutes := router.Group("/api/v1/public", middleware.RateLimit(5*time.Second))
	{
		publicRoutes.POST("/sign-up", api.SignUpHandler)
		publicRoutes.POST("/login", api.LoginHandler)
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
	}

	pdfRoutes := router.Group("/api/v1/pdf", middleware.JWTAuthMiddleware())
	{
		pdfRoutes.POST("/extract", api.ExtractPDFText)
		pdfRoutes.POST("/page-count", api.GetPDFPageCount)
		pdfRoutes.POST("/save", api.SaveStatement)
	}

	router.GET("/api/v1/transactions", middleware.JWTAuthMiddleware(), api.GetUserTransactionsHandler)

	log.Println("Server is running on port 8080")
	err = router.Run(":8080")
	if err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
