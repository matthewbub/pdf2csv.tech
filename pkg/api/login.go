package api

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

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
	username := utils.SanitizeInput(body.Username)
	password := utils.SanitizeInput(body.Password)
	user, err := getUserForLogin(username)

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

	// Generate JWT after successful login
	jwtToken, err := utils.GenerateJWT(user.ID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response.Error(
			"Failed to generate token",
			response.OPERATION_FAILED,
		))
		return
	}

	// Set cookie with JWT
	cookieConfig := struct {
		Expiration time.Duration
		Domain     string
		Secure     bool
		HttpOnly   bool
	}{
		Expiration: constants.AppConfig.DefaultJWTExpiration,
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

	c.SetCookie("jwt", jwtToken, int(cookieConfig.Expiration.Seconds()), "/", cookieConfig.Domain, cookieConfig.Secure, cookieConfig.HttpOnly)
	
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

func getUserForLogin(username string) (*utils.UserWithRole, error) {
	db := utils.GetDB()

	user := utils.UserWithRole{}
	tx, err := db.Begin()
	if err != nil {
		log.Println(err)
		return nil, err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("SELECT id, username, email, security_questions_answered, password, inactive_at FROM active_users WHERE username = ?")
	if err != nil {
		log.Println(err)
		return nil, err
	}
	defer stmt.Close()

	err = stmt.QueryRow(username).Scan(
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
