package middleware

import (
	"log"
	"net/http"
	"time"

	"bus.zcauldron.com/pkg/utils"
	"github.com/gin-gonic/gin"
)

func JWTAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Retrieve token from cookie
		tokenString, err := c.Cookie("jwt")
		if err != nil {
			log.Println("error getting token from cookie", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{})
			return
		}

		// Check if token is blacklisted (only for well-formed tokens)
		db := utils.GetDB()
		isBlacklisted, err := utils.IsTokenBlacklisted(db, tokenString)
		if err != nil {
			// If token is malformed, we'll catch it in the verification step
			log.Println("error checking token blacklist", err)
		} else if isBlacklisted {
			log.Println("token is blacklisted")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token has been revoked"})
			return
		}

		// Verify the token using the updated utils function
		userID, expTime, err := utils.VerifyJWT(tokenString)
		if err != nil {
			log.Println("error verifying token", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			return
		}

		// Check if token is expired (additional check)
		if time.Now().After(expTime) {
			log.Println("token expired")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
			return
		}

		// Store user ID in context for use in handlers
		c.Set("user_id", userID)

		log.Println("token is valid and not blacklisted; proceeding with the request")

		// Token is valid and not blacklisted; proceed with the request
		c.Next()
	}
}
