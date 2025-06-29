package api

import (
	"net/http"
	"time"

	"bus.zcauldron.com/pkg/api/response"
	"bus.zcauldron.com/pkg/constants"
	"bus.zcauldron.com/pkg/utils"
	"github.com/gin-gonic/gin"
)

func LogoutHandler(c *gin.Context) {
	env := utils.GetEnv()
	// Set cookie with JWT
	cookieConfig := struct {
		Expiration time.Duration
		Domain     string
		Secure     bool
		HttpOnly   bool
	}{
		Expiration: -1,
		Domain:     "",
		Secure:     true,
		HttpOnly:   true,
	}

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

	// Clear both JWT and refresh token cookies by setting expired cookies
	c.SetCookie("jwt", "", int(cookieConfig.Expiration.Seconds()), "/", cookieConfig.Domain, cookieConfig.Secure, cookieConfig.HttpOnly)
	c.SetCookie("refresh_token", "", int(cookieConfig.Expiration.Seconds()), "/", cookieConfig.Domain, cookieConfig.Secure, cookieConfig.HttpOnly)

	c.JSON(http.StatusOK, response.SuccessMessage(
		"Logged out successfully",
	))
}
