package utils

import (
	"errors"
	"time"

	"bus.zcauldron.com/pkg/constants"
	"github.com/golang-jwt/jwt/v5"
)

func GenerateJWT(userID string) (string, error) {
	jwtSecret := GetSecretKeyFromEnv()
	expiration := constants.AppConfig.DefaultJWTExpiration

	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(expiration).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func VerifyJWT(tokenString string) (string, time.Time, error) {
	token, err := jwt.Parse(tokenString, jwtSecretKeyFunc)
	if err != nil || !token.Valid {
		return "", time.Time{}, err
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", time.Time{}, errors.New("could not parse claims")
	}

	userID, ok := claims["user_id"].(string)
	if !ok {
		return "", time.Time{}, errors.New("user_id not found in token")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return "", time.Time{}, errors.New("expiration not found in token")
	}

	expirationTime := time.Unix(int64(exp), 0)

	return userID, expirationTime, nil
}

func jwtSecretKeyFunc(token *jwt.Token) (interface{}, error) {
	jwtSecret := GetSecretKeyFromEnv()
	if token.Method != jwt.SigningMethodHS256 {
		return nil, errors.New("unexpected signing method: only HS256 is allowed")
	}
	return jwtSecret, nil
}
