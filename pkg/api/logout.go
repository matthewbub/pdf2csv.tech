package api

import (
	"net/http"

	"bus.zcauldron.com/pkg/api/response"
	"bus.zcauldron.com/pkg/utils"
	"github.com/gin-gonic/gin"
)

func LogoutHandler(c *gin.Context) {
	// Set cookie with JWT
	cookieConfig := utils.GetCookieConfig(-1)

	// Clear both JWT and refresh token cookies by setting expired cookies
	c.SetCookie("jwt", "", int(cookieConfig.Expiration.Seconds()), "/", cookieConfig.Domain, cookieConfig.Secure, cookieConfig.HttpOnly)
	c.SetCookie("refresh_token", "", int(cookieConfig.Expiration.Seconds()), "/", cookieConfig.Domain, cookieConfig.Secure, cookieConfig.HttpOnly)

	c.JSON(http.StatusOK, response.SuccessMessage(
		"Logged out successfully",
	))
}
