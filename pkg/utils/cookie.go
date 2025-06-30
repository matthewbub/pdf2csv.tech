package utils

import (
	"time"

	"bus.zcauldron.com/pkg/constants"
)

type CookieConfig struct {
	Expiration time.Duration
	Domain     string
	Secure     bool
	HttpOnly   bool
}

func GetCookieConfig(expiration time.Duration) CookieConfig {
	env := GetEnv()

	config := CookieConfig{
		Expiration: expiration,
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
		config.Domain = d

		if env == constants.ENV_PRODUCTION {
			config.Secure = true
			config.HttpOnly = true
		}
		if env == constants.ENV_STAGING {
			config.HttpOnly = true
			config.Secure = true
		}
		if env == constants.ENV_DEVELOPMENT || env == constants.ENV_TEST {
			config.HttpOnly = false
			config.Secure = false
		}
	}

	return config
}
