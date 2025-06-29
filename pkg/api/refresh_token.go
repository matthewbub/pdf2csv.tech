package api

import (
	"net/http"

	"bus.zcauldron.com/pkg/api/response"
	"bus.zcauldron.com/pkg/constants"
	"bus.zcauldron.com/pkg/utils"
	"github.com/gin-gonic/gin"
)

func RefreshTokenHandler(c *gin.Context) {
	refreshToken, err := c.Cookie("refresh_token")
	if err != nil || refreshToken == "" {
		c.JSON(http.StatusUnauthorized, response.Error(
			"Refresh token not found",
			response.AUTHENTICATION_FAILED,
		))
		return
	}

	userID, _, err := utils.VerifyRefreshToken(refreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, response.Error(
			"Invalid refresh token",
			response.AUTHENTICATION_FAILED,
		))
		return
	}

	// Generate new access token
	newAccessToken, err := utils.GenerateJWT(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, response.Error(
			"Failed to generate access token",
			response.OPERATION_FAILED,
		))
		return
	}

	// Set cookie configuration
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

	// Set new access token cookie
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(
		"jwt",
		newAccessToken,
		int(constants.AppConfig.AccessTokenExpiration.Seconds()),
		"/",
		domain,
		secure,
		httpOnly,
	)

	c.JSON(http.StatusOK, response.SuccessMessage(
		"Access token refreshed successfully",
	))
}
