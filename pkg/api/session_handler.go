package api

import (
	"net/http"

	"bus.zcauldron.com/pkg/api/response"
	"bus.zcauldron.com/pkg/constants"
	"bus.zcauldron.com/pkg/utils"
	"github.com/gin-gonic/gin"
)

func RenewSessionHandler(c *gin.Context) {
	tokenString, err := c.Cookie("jwt")
	if err != nil || tokenString == "" {
		c.JSON(http.StatusUnauthorized, response.Error(
			"Authentication failed",
			response.AUTHENTICATION_FAILED,
		))
		return
	}

	userID, _, err := utils.VerifyJWT(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, response.Error(
			"Invalid token",
			response.AUTHENTICATION_FAILED,
		))
		return
	}

	// Generate new token
	newToken, err := utils.GenerateJWT(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response.Error(
			"Failed to generate token",
			response.OPERATION_FAILED,
		))
		return
	}

	var env = utils.GetEnv()
	domainMap := map[string]string{
		constants.ENV_PRODUCTION:  constants.AppConfig.ProductionDomain,
		constants.ENV_STAGING:     constants.AppConfig.StagingDomain,
		constants.ENV_DEVELOPMENT: constants.AppConfig.DevelopmentDomain,
		constants.ENV_TEST:        constants.AppConfig.TestDomain,
	}
	var domain string = ""
	var httpOnly bool = true
	var secure bool = true
	if d, ok := domainMap[env]; ok {
		domain = d
		if env == constants.ENV_STAGING {
			httpOnly = true
			secure = true
		}
		if env == constants.ENV_DEVELOPMENT || env == constants.ENV_TEST {
			httpOnly = false
			secure = false
		}
	}

	cookieName := "jwt"
	cookieValue := newToken
	maxAge := int(constants.AppConfig.AccessTokenExpiration.Seconds())
	path := "/"

	// Set new cookie
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(
		cookieName,
		cookieValue,
		maxAge,
		path,
		domain,
		secure,
		httpOnly,
	)

	c.JSON(http.StatusOK, response.SuccessMessage(
		"Session renewed successfully",
	))
}
