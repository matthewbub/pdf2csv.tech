package api

import (
	"fmt"
	"net/http"
	"time"

	"bus.zcauldron.com/pkg/api/response"
	"bus.zcauldron.com/pkg/constants"
	"bus.zcauldron.com/pkg/utils"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func SignUpHandler(c *gin.Context) {
	logger := utils.GetLogger()

	// Parse request body as JSON
	var body struct {
		Username        string `json:"username"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirmPassword"`
		Email           string `json:"email"`
		TermsAccepted   bool   `json:"termsAccepted"`
	}

	if err := c.ShouldBindJSON(&body); err != nil {
		logger.Printf("Invalid request data: %v", err)
		c.JSON(http.StatusBadRequest, response.Error(
			"Invalid request data",
			response.INVALID_REQUEST_DATA,
		))
		return
	}

	// BEGIN DATA VALIDATION
	if err := validateSignUpData(&body); err != nil {
		logger.Printf("Data validation error: %v", err)
		var errorCode string
		switch err.Error() {
		case "weak password":
			errorCode = response.WEAK_PASSWORD
		case "passwords do not match":
			errorCode = response.PASSWORD_MISMATCH
		default:
			errorCode = response.INVALID_REQUEST_DATA
		}
		c.JSON(http.StatusBadRequest, response.Error(
			err.Error(),
			errorCode,
		))
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		logger.Printf("Error hashing password: %v", err)
		c.JSON(http.StatusInternalServerError, response.Error(
			"Server error",
			response.OPERATION_FAILED,
		))
		return
	}

	// Insert user into the database
	userID, err := insertUserIntoDatabase(body.Username, string(hashedPassword), body.Email)
	if err != nil {
		logger.Printf("Database insertion error: %v", err)
		c.JSON(http.StatusConflict, response.Error(
			"Username or email already exists",
			response.OPERATION_FAILED,
		))
		return
	}

	// Generate access and refresh tokens
	accessToken, refreshToken, err := utils.GenerateTokenPair(userID)
	if err != nil {
		logger.Printf("Token generation error: %v", err)
		c.JSON(http.StatusInternalServerError, response.Error(
			"Failed to generate tokens",
			response.AUTHENTICATION_FAILED,
		))
		return
	}

	cookieConfig := struct {
		Expiration time.Duration
		Domain     string
		Secure     bool
		HttpOnly   bool
	}{
		Expiration: constants.AppConfig.AccessTokenExpiration,
		Domain:     "",
		Secure:     true,
		HttpOnly:   true,
	}

	env := utils.GetEnv()
	domainMap := map[string]string{
		constants.ENV_PRODUCTION:  constants.AppConfig.ProductionDomain,
		constants.ENV_STAGING:     constants.AppConfig.StagingDomain,
		constants.ENV_DEVELOPMENT: constants.AppConfig.DevelopmentDomain,
		constants.ENV_TEST:        constants.AppConfig.TestDomain,
	}

	if d, ok := domainMap[env]; ok {
		cookieConfig.Domain = d

		if env == constants.ENV_PRODUCTION {
			cookieConfig.Secure = true
			cookieConfig.HttpOnly = true
		}
		if env == constants.ENV_STAGING || env == constants.ENV_DEVELOPMENT || env == constants.ENV_TEST {
			cookieConfig.HttpOnly = false
			cookieConfig.Secure = false
		}
	}

	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie("jwt", accessToken, int(cookieConfig.Expiration.Seconds()), "/", cookieConfig.Domain, cookieConfig.Secure, cookieConfig.HttpOnly)
	c.SetCookie("refresh_token", refreshToken, int(constants.AppConfig.RefreshTokenExpiration.Seconds()), "/", cookieConfig.Domain, cookieConfig.Secure, cookieConfig.HttpOnly)
	c.JSON(http.StatusOK, response.SuccessMessage(
		"Account registration completed successfully",
	))
}

func validateSignUpData(body *struct {
	Username        string `json:"username"`
	Password        string `json:"password"`
	ConfirmPassword string `json:"confirmPassword"`
	Email           string `json:"email"`
	TermsAccepted   bool   `json:"termsAccepted"`
}) error {
	if !body.TermsAccepted {
		return fmt.Errorf("terms must be accepted")
	}
	if !utils.IsValidUsername(body.Username) {
		return fmt.Errorf("invalid username")
	}
	if !utils.IsValidEmail(body.Email) {
		return fmt.Errorf("invalid email")
	}
	if body.Password != body.ConfirmPassword {
		return fmt.Errorf("passwords do not match")
	}
	if err := utils.ValidatePasswordStrength(body.Password); err != nil {
		return fmt.Errorf("weak password")
	}
	return nil
}

func insertUserIntoDatabase(username, hashedPassword, email string) (string, error) {
	db := utils.GetDB()
	logger := utils.GetLogger()

	if db == nil {
		logger.Println("Database connection is nil")
		return "", fmt.Errorf("database connection not established")
	}

	stmt, err := db.Prepare("INSERT INTO users (id, username, password, email, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)")
	if err != nil {
		logger.Printf("Failed to prepare user insert statement: %v", err)
		return "", fmt.Errorf("failed to prepare statement: %w", err)
	}
	defer stmt.Close()

	userID := uuid.New().String()
	_, err = stmt.Exec(userID, username, hashedPassword, email, time.Now(), time.Now())
	if err != nil {
		logger.Printf("Failed to execute user insert statement: %v", err)
		return "", fmt.Errorf("failed to insert user: %w", err)
	}

	stmtHist, err := db.Prepare("INSERT INTO password_history (user_id, password) VALUES (?, ?)")
	if err != nil {
		logger.Printf("Failed to prepare password history statement: %v", err)
		return "", fmt.Errorf("failed to prepare password history statement: %w", err)
	}
	defer stmtHist.Close()

	_, err = stmtHist.Exec(userID, hashedPassword)
	if err != nil {
		logger.Printf("Failed to insert password into history: %v", err)
		return "", fmt.Errorf("failed to insert password into history: %w", err)
	}

	return userID, nil
}
