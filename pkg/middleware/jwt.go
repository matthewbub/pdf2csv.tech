package middleware

import (
	"errors"
	"log"
	"net/http"
	"time"

	"bus.zcauldron.com/pkg/utils"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func JWTAuthMiddleware() gin.HandlerFunc {
	jwtSecretKey := utils.GetSecretKeyFromEnv()
	return func(c *gin.Context) {
		// Retrieve token from cookie
		tokenString, err := c.Cookie("jwt")
		if err != nil {
			log.Println("error getting token from cookie", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{})
			return
		}

		// Parse the token with the MapClaims type
		token, err := jwt.ParseWithClaims(tokenString, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
			if token.Method != jwt.SigningMethodHS256 {
				return nil, errors.New("unexpected signing method: only HS256 is allowed")
			}
			return []byte(jwtSecretKey), nil
		})

		if err != nil || !token.Valid {
			log.Println("error parsing token", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			return
		}

		// Type assertion to access claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			log.Println("error getting token claims")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
			return
		}

		// Check expiration time (exp) claim
		if exp, ok := claims["exp"].(float64); ok {
			if time.Unix(int64(exp), 0).Before(time.Now()) {
				log.Println("token expired")
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
				return
			}
		} else {
			log.Println("invalid token expiration")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token expiration"})
			return
		}

		log.Println("token is valid and not expired; proceeding with the request")

		// Token is valid and not expired; proceed with the request
		c.Next()
	}
}
