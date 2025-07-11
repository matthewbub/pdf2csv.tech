package api

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"

	"bus.zcauldron.com/pkg/api/response"
	"bus.zcauldron.com/pkg/constants"
	"bus.zcauldron.com/pkg/middleware"
	"bus.zcauldron.com/pkg/utils"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func LoginHandler(c *gin.Context) {
	var body struct {
		Username   string `json:"username"`
		Email      string `json:"email"`
		Password   string `json:"password"`
		RememberMe bool   `json:"rememberMe"`
	}
	err := c.BindJSON(&body)
	if err != nil {
		c.JSON(http.StatusBadRequest, response.Error(
			"Invalid request body",
			response.INVALID_REQUEST_DATA,
		))
		return
	}

	// Support login by either username or email
	identifier := utils.SanitizeInput(body.Username)

	if identifier == "" {
		// If using email, validate email format before sanitizing
		if body.Email != "" && !utils.IsValidEmail(body.Email) {
			c.JSON(http.StatusBadRequest, response.Error(
				"Invalid email format",
				response.INVALID_REQUEST_DATA,
			))
			return
		}
		identifier = utils.SanitizeInput(body.Email)
	}

	if identifier == "" {
		c.JSON(http.StatusBadRequest, response.Error(
			"Username or email is required",
			response.INVALID_REQUEST_DATA,
		))
		return
	}

	password := utils.SanitizeInput(body.Password)
	if password == "" {
		c.JSON(http.StatusBadRequest, response.Error(
			"Password is required",
			response.INVALID_REQUEST_DATA,
		))
		return
	}

	user, err := getUserForLogin(identifier)

	// Basic validation
	if err != nil || user == nil || bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
		middleware.RecordFailedLogin(c.ClientIP())
		c.JSON(http.StatusUnauthorized, response.Error(
			"Invalid username or password",
			response.AUTHENTICATION_FAILED,
		))
		return
	}

	// Check if user is inactive
	if user.InactiveAt.Valid {
		log.Println("User is inactive", user.ID)
		middleware.RecordFailedLogin(c.ClientIP())
		c.JSON(http.StatusUnauthorized, response.Error(
			"User is inactive",
			response.AUTHENTICATION_FAILED,
		))
		return
	}

	// Generate access and refresh tokens after successful login
	accessToken, refreshToken, err := utils.GenerateTokenPair(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response.Error(
			"Failed to generate tokens",
			response.OPERATION_FAILED,
		))
		return
	}

	// Set cookie with JWT
	cookieConfig := utils.GetCookieConfig(constants.AppConfig.AccessTokenExpiration)

	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie("jwt", accessToken, int(cookieConfig.Expiration.Seconds()), "/", cookieConfig.Domain, cookieConfig.Secure, cookieConfig.HttpOnly)
	c.SetCookie("refresh_token", refreshToken, int(constants.AppConfig.RefreshTokenExpiration.Seconds()), "/", cookieConfig.Domain, cookieConfig.Secure, cookieConfig.HttpOnly)

	// Clear failed login attempts on successful login
	middleware.RecordSuccessfulLogin(c.ClientIP())

	c.JSON(http.StatusOK, response.Success(
		struct {
			SecurityQuestionsAnswered bool `json:"securityQuestionsAnswered"`
		}{
			SecurityQuestionsAnswered: user.SecurityQuestionsAnswered,
		},
		"Logged in successfully",
	))
}

func getUserForLogin(identifier string) (*utils.UserWithRole, error) {
	db := utils.GetDB()

	user := utils.UserWithRole{}
	tx, err := db.Begin()
	if err != nil {
		log.Println(err)
		return nil, err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("SELECT id, username, email, security_questions_answered, password, inactive_at FROM active_users WHERE username = ? OR email = ?")
	if err != nil {
		log.Println(err)
		return nil, err
	}
	defer stmt.Close()

	err = stmt.QueryRow(identifier, identifier).Scan(
		&user.ID,
		&user.Username,
		&user.Email,
		&user.SecurityQuestionsAnswered,
		&user.Password,
		&user.InactiveAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("user not found")
		}
		log.Println(err)
		return nil, err
	}

	// update the user's last login
	// stmt, err = tx.Prepare("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?")
	// if err != nil {
	// 	log.Println(err)
	// 	return nil, err
	// }
	// _, err = stmt.Exec(user.ID)
	// if err != nil {
	// 	log.Println(err)
	// 	return nil, err
	// }

	if err = tx.Commit(); err != nil {
		log.Println(err)
		return nil, err
	}

	return &user, nil
}
