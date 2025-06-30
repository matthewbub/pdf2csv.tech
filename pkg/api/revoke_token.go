package api

import (
	"log"
	"net/http"

	"bus.zcauldron.com/pkg/api/response"
	"bus.zcauldron.com/pkg/utils"
	"github.com/gin-gonic/gin"
)

func RevokeTokenHandler(c *gin.Context) {
	db := utils.GetDB()
	if db == nil {
		log.Println("Database connection not available")
		c.JSON(http.StatusInternalServerError, response.Error(
			"Internal server error",
			"Database connection not available",
		))
		return
	}

	// Get the current token from cookie
	tokenString, err := c.Cookie("jwt")
	if err != nil {
		log.Println("Error getting token from cookie:", err)
		c.JSON(http.StatusUnauthorized, response.Error(
			"Unauthorized",
			"No token provided",
		))
		return
	}

	// Blacklist the current token
	err = utils.BlacklistToken(db, tokenString, "user_revoked")
	if err != nil {
		log.Println("Error blacklisting token:", err)
		c.JSON(http.StatusInternalServerError, response.Error(
			"Internal server error",
			"Failed to revoke token",
		))
		return
	}

	// Also try to blacklist refresh token if present
	refreshToken, err := c.Cookie("refresh_token")
	if err == nil && refreshToken != "" {
		err = utils.BlacklistToken(db, refreshToken, "user_revoked")
		if err != nil {
			log.Println("Warning: Failed to blacklist refresh token:", err)
		}
	}

	// Clear the cookies
	cookieConfig := utils.GetCookieConfig(-1)

	c.SetCookie("jwt", "", int(cookieConfig.Expiration.Seconds()), "/", cookieConfig.Domain, cookieConfig.Secure, cookieConfig.HttpOnly)
	c.SetCookie("refresh_token", "", int(cookieConfig.Expiration.Seconds()), "/", cookieConfig.Domain, cookieConfig.Secure, cookieConfig.HttpOnly)

	c.JSON(http.StatusOK, response.SuccessMessage(
		"Token revoked successfully",
	))
}

func RevokeAllTokensHandler(c *gin.Context) {
	db := utils.GetDB()
	if db == nil {
		log.Println("Database connection not available")
		c.JSON(http.StatusInternalServerError, response.Error(
			"Internal server error",
			"Database connection not available",
		))
		return
	}

	// Get user ID from context (set by JWT middleware)
	userIDInterface, exists := c.Get("user_id")
	if !exists {
		log.Println("User ID not found in context")
		c.JSON(http.StatusUnauthorized, response.Error(
			"Unauthorized",
			"User not authenticated",
		))
		return
	}

	userID, ok := userIDInterface.(string)
	if !ok {
		log.Println("Invalid user ID type in context")
		c.JSON(http.StatusInternalServerError, response.Error(
			"Internal server error",
			"Invalid user context",
		))
		return
	}

	// Blacklist all tokens for this user
	err := utils.BlacklistAllUserTokens(db, userID, "user_revoked_all")
	if err != nil {
		log.Println("Error blacklisting all user tokens:", err)
		c.JSON(http.StatusInternalServerError, response.Error(
			"Internal server error",
			"Failed to revoke all tokens",
		))
		return
	}

	// Clear the cookies
	cookieConfig := utils.GetCookieConfig(-1)

	c.SetCookie("jwt", "", int(cookieConfig.Expiration.Seconds()), "/", cookieConfig.Domain, cookieConfig.Secure, cookieConfig.HttpOnly)
	c.SetCookie("refresh_token", "", int(cookieConfig.Expiration.Seconds()), "/", cookieConfig.Domain, cookieConfig.Secure, cookieConfig.HttpOnly)

	c.JSON(http.StatusOK, response.SuccessMessage(
		"All tokens revoked successfully",
	))
}
